#ifndef OTA_TASK_H
#define OTA_TASK_H

/**
 * Starts the OTA download-and-apply task as a FreeRTOS task.
 * Call this once from app_main(), after any other setup you need
 * to run first.
 *
 * The task itself connects to Wi-Fi, downloads the firmware bundle,
 * decrypts and verifies it, flashes it to the inactive OTA partition,
 * and reboots on success.
 */
void ota_task_start(void);

#endif // OTA_TASK_H