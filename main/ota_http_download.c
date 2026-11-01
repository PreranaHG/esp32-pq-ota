#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "ota_http_download.h"

static const char *TAG = "ota_http";

#define HEADER_FIXED_BYTES (MLKEM_CIPHERTEXTBYTES(512) + MLDSA44_BYTES + CRYPTO_VERIFY_TAG_BYTES + 4)

// Read exactly `len` bytes from the HTTP stream (esp_http_client_read may return less).
esp_err_t ota_http_read_exact(esp_http_client_handle_t client, uint8_t *dst, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = esp_http_client_read(client, (char *)dst + got, len - got);
        if (n < 0) {
            ESP_LOGE(TAG, "HTTP read error");
            return ESP_FAIL;
        }
        if (n == 0) {
            // no data yet, or connection closed
            if (esp_http_client_is_complete_data_received(client)) {
                ESP_LOGE(TAG, "Stream ended early (%zu/%zu bytes)", got, len);
                return ESP_FAIL;
            }
            continue;
        }
        got += (size_t)n;
    }
    return ESP_OK;
}

esp_err_t ota_download_bundle_header(const char *url, ota_bundle_stream_t *out)
{
    memset(out, 0, sizeof(*out));

    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cannot open connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    int64_t content_len = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    ESP_LOGI(TAG, "HTTP status=%d, content-length=%lld", status, (long long)content_len);

    if (status != 200 || content_len < (int64_t)HEADER_FIXED_BYTES) {
        ESP_LOGE(TAG, "Bad response (status/size)");
        err = ESP_FAIL;
        goto fail;
    }

    // Fixed-size header: ct_kem | sig | tag | length
    uint8_t len_le[4];
    if ((err = ota_http_read_exact(client, out->ct_kem, sizeof(out->ct_kem))) != ESP_OK) goto fail;
    if ((err = ota_http_read_exact(client, out->sig,    sizeof(out->sig)))    != ESP_OK) goto fail;
    if ((err = ota_http_read_exact(client, out->tag,    sizeof(out->tag)))    != ESP_OK) goto fail;
    if ((err = ota_http_read_exact(client, len_le,      sizeof(len_le)))      != ESP_OK) goto fail;

    size_t ct_len = (size_t)len_le[0] | ((size_t)len_le[1] << 8) |
                    ((size_t)len_le[2] << 16) | ((size_t)len_le[3] << 24);

    if (ct_len == 0 || ct_len > OTA_MAX_CIPHERTEXT_BYTES ||
        (int64_t)(HEADER_FIXED_BYTES + ct_len) != content_len) {
        ESP_LOGE(TAG, "Invalid ciphertext length %zu (content-length %lld)", ct_len, (long long)content_len);
        err = ESP_ERR_INVALID_SIZE;
        goto fail;
    }

    out->ciphertext_len = ct_len;
    out->client = client;  // left OPEN — caller streams the ciphertext body directly from here
    ESP_LOGI(TAG, "Header OK, %zu ciphertext bytes to stream", ct_len);
    return ESP_OK;

fail:
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return err;
}

void ota_bundle_stream_close(ota_bundle_stream_t *stream)
{
    if (stream && stream->client) {
        esp_http_client_close(stream->client);
        esp_http_client_cleanup(stream->client);
        stream->client = NULL;
    }
}