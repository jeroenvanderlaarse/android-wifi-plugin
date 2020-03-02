/*
 * Copyright 2020 Jeroen van der Laarse
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

var AndroidWifi = {

    /**
     * Connect network with specified ssid
     *
     * This method will first add the wifi configuration, then enable the network, returning promise when connection is verified.
     *
     * @param {string|int} [ssid]
    * @param {string} [password=]
     * @param {string} [algorithm=NONE]            WPA, WPA (for WPA2), WEP or NONE (NONE by default)
     * @returns {Promise<any>}
     */
    connect: function (ssid, password, authType) {
        return new Promise(function (resolve, reject) {

            if (!ssid) {
                reject('ssid is missing!');
                return;
            }

            if (!authType) {
                reject('authType is missing!');
                return;
            }

            cordova.exec(resolve, reject, "AndroidWifi", "connect", [
                { 
                    "ssid": ssid, 
                    "password" : password, 
                    "authType" : authType
                }
            ]);
        });
    },

    /**
     * Disconnect (current if ssid not supplied)
     *
     * This method, if passed an ssid, will first disable the network, and then remove it from the device.  To only "disconnect" (ie disable in android),
     * call AndroidWifi.disable() instead of disconnect.
     *
     * @param {string|int} [ssid=all]
     * @returns {Promise<any>}
     */
    disconnect: function (ssid) {
        return new Promise(function (resolve, reject) {

            if (!ssid) {
                reject('ssid is missing!');
                return;
            }

            cordova.exec(resolve, reject, "AndroidWifi", "disconnect", [
                { "ssid": ssid
                }
            ]);
            
        });
    }
};

module.exports = AndroidWifi;