#ifndef WIFI_INIT_H
#define WIFI_INIT_H

#include "esp_err.h"

/**
 * Initialise NVS, the network stack and Wi-Fi in station mode, connect to
 * the given access point, and block until an IP address is obtained
 * (or the retry limit is hit).
 *
 * Returns ESP_OK once connected, ESP_FAIL if it could not connect.
 */
esp_err_t wifi_init_sta(const char *ssid, const char *password);

#endif // WIFI_INIT_H