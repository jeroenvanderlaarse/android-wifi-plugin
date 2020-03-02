package androidwifi;


import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.AsyncTask;
import android.os.Build;
import android.os.PatternMatcher;
import android.provider.Settings;
import android.util.Log;


import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

public class AndroidWifi extends CordovaPlugin {

    private static String TAG = "AndroidWifi";
    private static final int API_VERSION = Build.VERSION.SDK_INT;

    private static final String ADD_NETWORK = "add";
  private static final String REMOVE_NETWORK = "remove";
  private static final String CONNECT_NETWORK = "connect";
  private static final String DISCONNECT_NETWORK = "disconnectNetwork";
  private static final String DISCONNECT = "disconnect";
  private static final String LIST_NETWORKS = "listNetworks";
  private static final String START_SCAN = "startScan";
  private static final String GET_SCAN_RESULTS = "getScanResults";
  private static final String GET_CONNECTED_SSID = "getConnectedSSID";
  private static final String GET_CONNECTED_BSSID = "getConnectedBSSID";
  private static final String GET_CONNECTED_NETWORKID = "getConnectedNetworkID";
  private static final String IS_WIFI_ENABLED = "isWifiEnabled";
  private static final String SET_WIFI_ENABLED = "setWifiEnabled";
  private static final String SCAN = "scan";
  private static final String ENABLE_NETWORK = "enable";
  private static final String DISABLE_NETWORK = "disable";
  private static final String GET_SSID_NET_ID = "getSSIDNetworkID";
  private static final String REASSOCIATE = "reassociate";
  private static final String RECONNECT = "reconnect";
  private static final String REQUEST_FINE_LOCATION = "requestFineLocation";
  private static final String GET_WIFI_IP_ADDRESS = "getWifiIP";
  private static final String GET_WIFI_ROUTER_IP_ADDRESS = "getWifiRouterIP";
  private static final String CAN_PING_WIFI_ROUTER = "canPingWifiRouter";
  private static final String CAN_CONNECT_TO_ROUTER = "canConnectToRouter";
  private static final String CAN_CONNECT_TO_INTERNET = "canConnectToInternet";
  private static final String IS_CONNECTED_TO_INTERNET = "isConnectedToInternet";
  private static final String RESET_BIND_ALL = "resetBindAll";
  private static final String SET_BIND_ALL = "setBindAll";
  private static final String GET_WIFI_IP_INFO = "getWifiIPInfo";

    private WifiManager wifiManager;
    private CallbackContext callbackContext;
    private JSONArray passedData;
  
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
  
    // Store AP, previous, and desired wifi info
    private AP previous, desired;
  
    private final BroadcastReceiver networkChangedReceiver = new NetworkChangedReceiver();
    private static final IntentFilter NETWORK_STATE_CHANGED_FILTER = new IntentFilter();
  
    static {
      NETWORK_STATE_CHANGED_FILTER.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);
    }


  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    this.wifiManager = (WifiManager) cordova.getActivity().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
    this.connectivityManager = (ConnectivityManager) cordova.getActivity().getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
  }

  @Override
  public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
      throws JSONException {

    this.callbackContext = callbackContext;
    this.passedData = data;

    // Actions that do not require WiFi to be enabled
    if (action.equals(IS_WIFI_ENABLED)) {
      this.isWifiEnabled(callbackContext);
      return true;
    } else if (action.equals(SET_WIFI_ENABLED)) {
      this.setWifiEnabled(callbackContext, data);
      return true;
    } else if (action.equals(REQUEST_FINE_LOCATION)) {
      this.requestLocationPermission(LOCATION_REQUEST_CODE);
      return true;
    } else if (action.equals(GET_WIFI_ROUTER_IP_ADDRESS)) {

      String ip = getWiFiRouterIP();

      if ( ip == null || ip.equals("0.0.0.0")) {
        callbackContext.error("NO_VALID_ROUTER_IP_FOUND");
        return true;
      } else {
        callbackContext.success(ip);
        return true;
      }

    } else if (action.equals(GET_WIFI_IP_ADDRESS) || action.equals(GET_WIFI_IP_INFO)) {
      String[] ipInfo = getWiFiIPAddress();
      String ip = ipInfo[0];
      String subnet = ipInfo[1];
      if (ip == null || ip.equals("0.0.0.0")) {
        callbackContext.error("NO_VALID_IP_IDENTIFIED");
        return true;
      }

      // Return only IP address
      if( action.equals( GET_WIFI_IP_ADDRESS ) ){
        callbackContext.success(ip);
        return true;
      }

      // Return Wifi IP Info (subnet and IP as JSON object)
      JSONObject result = new JSONObject();

      result.put("ip", ip);
      result.put("subnet", subnet);

      callbackContext.success(result);
      return true;
    }

    boolean wifiIsEnabled = verifyWifiEnabled();
    if (!wifiIsEnabled) {
      callbackContext.error("WIFI_NOT_ENABLED");
      return true; // Even though enable wifi failed, we still return true and handle error in callback
    }

    // Actions that DO require WiFi to be enabled
    if (action.equals(ADD_NETWORK)) {
      this.add(callbackContext, data);
    } else if (action.equals(IS_CONNECTED_TO_INTERNET)) {
      this.canConnectToInternet(callbackContext, true);
    } else if (action.equals(CAN_CONNECT_TO_INTERNET)) {
      this.canConnectToInternet(callbackContext, false);
    } else if (action.equals(CAN_PING_WIFI_ROUTER)) {
      this.canConnectToRouter(callbackContext, true);
    } else if (action.equals(CAN_CONNECT_TO_ROUTER)) {
      this.canConnectToRouter(callbackContext, false);
    } else if (action.equals(ENABLE_NETWORK)) {
      this.enable(callbackContext, data);
    } else if (action.equals(DISABLE_NETWORK)) {
      this.disable(callbackContext, data);
    } else if (action.equals(GET_SSID_NET_ID)) {
      this.getSSIDNetworkID(callbackContext, data);
    } else if (action.equals(REASSOCIATE)) {
      this.reassociate(callbackContext);
    } else if (action.equals(RECONNECT)) {
      this.reconnect(callbackContext);
    } else if (action.equals(SCAN)) {
      this.scan(callbackContext, data);
    } else if (action.equals(REMOVE_NETWORK)) {
      this.remove(callbackContext, data);
    } else if (action.equals(CONNECT_NETWORK)) {
      this.connect(callbackContext, data);
    } else if (action.equals(DISCONNECT_NETWORK)) {
      this.disconnectNetwork(callbackContext, data);
    } else if (action.equals(LIST_NETWORKS)) {
      this.listNetworks(callbackContext);
    } else if (action.equals(START_SCAN)) {
      this.startScan(callbackContext);
    } else if (action.equals(GET_SCAN_RESULTS)) {
      this.getScanResults(callbackContext, data);
    } else if (action.equals(DISCONNECT)) {
      this.disconnect(callbackContext);
    } else if (action.equals(GET_CONNECTED_SSID)) {
      this.getConnectedSSID(callbackContext);
    } else if (action.equals(GET_CONNECTED_BSSID)) {
      this.getConnectedBSSID(callbackContext);
    } else if (action.equals(GET_CONNECTED_NETWORKID)) {
      this.getConnectedNetworkID(callbackContext);
    } else if (action.equals(RESET_BIND_ALL)) {
      this.resetBindAll(callbackContext);
    } else if (action.equals(SET_BIND_ALL)) {
      this.setBindAll(callbackContext);
    } else {
      callbackContext.error("Incorrect action parameter: " + action);
      // The ONLY time to return FALSE is when action does not exist that was called
      // Returning false results in an INVALID_ACTION error, which translates to an error callback invoked on the JavaScript side
      // All other errors should be handled with the fail callback (callbackContext.error)
      // @see https://cordova.apache.org/docs/en/latest/guide/platforms/android/plugin.html
      return false;
    }

    return true;
  }

/**
   * This methods adds a network to the list of available WiFi networks. If the network already
   * exists, then it updates it.
   *
   * @return true    if add successful, false if add fails
   * @params callbackContext     A Cordova callback context.
   * @params data                JSON Array with [0] == SSID, [1] == password
   */
  private boolean add(CallbackContext callbackContext, JSONArray data) {

    Log.d(TAG, "WifiWizard2: add entered.");

    // Initialize the WifiConfiguration object
    WifiConfiguration wifi = new WifiConfiguration();

    try {
      // data's order for ANY object is
      // 0: SSID
      // 1: authentication algorithm,
      // 2: authentication information
      // 3: whether or not the SSID is hidden
      String newSSID = data.getString(0);
      String authType = data.getString(1);
      String newPass = data.getString(2);
      boolean isHiddenSSID = data.getBoolean(3);

      wifi.hiddenSSID = isHiddenSSID;

      if (authType.equals("WPA") || authType.equals("WPA2")) {
       /**
        * WPA Data format:
        * 0: ssid
        * 1: auth
        * 2: password
        * 3: isHiddenSSID
        */
        wifi.SSID = newSSID;
        wifi.preSharedKey = newPass;

        wifi.status = WifiConfiguration.Status.ENABLED;
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

        wifi.networkId = ssidToNetworkId(newSSID);

      } else if (authType.equals("WEP")) {
       /**
        * WEP Data format:
        * 0: ssid
        * 1: auth
        * 2: password
        * 3: isHiddenSSID
        */
        wifi.SSID = newSSID;

        if (getHexKey(newPass)) {
          wifi.wepKeys[0] = newPass;
        } else {
          wifi.wepKeys[0] = "\"" + newPass + "\"";
        }
        wifi.wepTxKeyIndex = 0;

        wifi.status = WifiConfiguration.Status.ENABLED;
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
        wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
        wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

        wifi.networkId = ssidToNetworkId(newSSID);

      } else if (authType.equals("NONE")) {
       /**
        * OPEN Network data format:
        * 0: ssid
        * 1: auth
        * 2: <not used>
        * 3: isHiddenSSID
        */
        wifi.SSID = newSSID;
        wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
        wifi.networkId = ssidToNetworkId(newSSID);

      } else {

        Log.d(TAG, "Wifi Authentication Type Not Supported.");
        callbackContext.error("AUTH_TYPE_NOT_SUPPORTED");
        return false;

      }

      // Set network to highest priority (deprecated in API >= 26)
      if( API_VERSION < 26 ){
        wifi.priority = getMaxWifiPriority(wifiManager) + 1;
      }

      // After processing authentication types, add or update network
      if (wifi.networkId == -1) { // -1 means SSID configuration does not exist yet

        int newNetId = wifiManager.addNetwork(wifi);
        if( newNetId > -1 ){
          callbackContext.success( newNetId );
        } else {
          callbackContext.error( "ERROR_ADDING_NETWORK" );
        }

      } else {

        int updatedNetID = wifiManager.updateNetwork(wifi);

        if( updatedNetID > -1 ){
          callbackContext.success( updatedNetID );
        } else {
          callbackContext.error( "ERROR_UPDATING_NETWORK" );
        }

      }

      // WifiManager configurations are presistent for API 26+
      if (API_VERSION < 26) {
        wifiManager.saveConfiguration(); // Call saveConfiguration for older < 26 API
      }

      return true;


    } catch (Exception e) {
      callbackContext.error(e.getMessage());
      Log.d(TAG, e.getMessage());
      return false;
    }
  }


  public void connect(CallbackContext callbackContext, JSONArray data) {
    Log.d(TAG, "WifiWizard2: connect entered.");

    if (!validateData(data)) {
      callbackContext.error("CONNECT_INVALID_DATA");
      Log.d(TAG, "WifiWizard2: connect invalid data.");
      return;
    }


    if (API_VERSION < 29) {
        String ssid = "\"" + data.getString("ssid") + "\"";
        String password =  "\"" + data.getString("password") + "\"";
        String authType = data.getString("authType");
        this.add(call, ssid, password, authType);

        int networkIdToConnect = ssidToNetworkId(ssid, authType);

        if (networkIdToConnect > -1) {
            this.forceWifiUsage(false);
            wifiManager.enableNetwork(networkIdToConnect, true);
            this.forceWifiUsage(true);

            // Wait for connection to finish, otherwise throw a timeout error
            new ConnectAsync().execute(callbackContext, networkIdToConnect, this);

        } else {
            callbackContext.error("INVALID_NETWORK_ID_TO_CONNECT");
        }
    } else {

        String ssid = callbackContext.getString("ssid");
        String password =  callbackContext.getString("password");

        String connectedSSID = this.getWifiServiceInfo(callbackContext);

        if (!ssid.equals(connectedSSID)) {

            WifiNetworkSpecifier.Builder builder = new WifiNetworkSpecifier.Builder();
            builder.setSsid(ssid);
            if (password != null && password.length() > 0) {
                builder.setWpa2Passphrase(password);
            }

            WifiNetworkSpecifier wifiNetworkSpecifier = builder.build();
            NetworkRequest.Builder networkRequestBuilder = new NetworkRequest.Builder();
            networkRequestBuilder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
            networkRequestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
            networkRequestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED);
            networkRequestBuilder.setNetworkSpecifier(wifiNetworkSpecifier);
            NetworkRequest networkRequest = networkRequestBuilder.build();
            this.forceWifiUsageQ(true, networkRequest);
        } else {
            this.getConnectedSSID(call);
        }
    }
    }


      /**
   * This method disconnects a network.
   *
   * @param callbackContext A Cordova callback context
   * @param data JSON Array, with [0] being SSID to connect
   * @return true if network disconnected, false if failed
   */
  private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
    Log.d(TAG, "WifiWizard2: disconnectNetwork entered.");
    if (!validateData(data)) {
      callbackContext.error("DISCONNECT_NET_INVALID_DATA");
      Log.d(TAG, "WifiWizard2: disconnectNetwork invalid data");
      return false;
    }

    String ssidToDisconnect = "";

    // TODO: Verify type of data here!
    try {
      ssidToDisconnect = data.getString(0);
    } catch (Exception e) {
      callbackContext.error(e.getMessage());
      Log.d(TAG, e.getMessage());
      return false;
    }

    int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect);

    if (networkIdToDisconnect > 0) {

      if( wifiManager.disableNetwork(networkIdToDisconnect) ){

        maybeResetBindALL();

        // We also remove the configuration from the device (use "disable" to keep config)
        if( wifiManager.removeNetwork(networkIdToDisconnect) ){
          callbackContext.success("Network " + ssidToDisconnect + " disconnected and removed!");
        } else {
          callbackContext.error("DISCONNECT_NET_REMOVE_ERROR");
          Log.d(TAG, "WifiWizard2: Unable to remove network!");
          return false;
        }

      } else {
        callbackContext.error("DISCONNECT_NET_DISABLE_ERROR");
        Log.d(TAG, "WifiWizard2: Unable to disable network!");
        return false;
      }

      return true;
    } else {
      callbackContext.error("DISCONNECT_NET_ID_NOT_FOUND");
      Log.d(TAG, "WifiWizard2: Network not found to disconnect.");
      return false;
    }
  }

  /**
   * Validate JSON data
   */
  private boolean validateData(JSONArray data) {
    try {
      if (data == null || data.get(0) == null) {
        callbackContext.error("DATA_IS_NULL");
        return false;
      }
      return true;
    } catch (Exception e) {
      callbackContext.error(e.getMessage());
    }
    return false;
  }

  private int ssidToNetworkId(String ssid, String authType) {
    try {

        int maybeNetId = Integer.parseInt(ssid);
        return maybeNetId;

    } catch (NumberFormatException e) {
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
        int networkId = -1;
        // For each network in the list, compare the SSID with the given one and check if authType matches
        Log.i(TAG, "MyNetwork: " + ssid + "|" + authType);

        for (WifiConfiguration network : currentNetworks) {
            Log.i(TAG, "Network: " + network.SSID + "|" + this.getSecurityType(network));

            if (network.SSID != null) {
                if (authType.length() == 0) {
                    if(network.SSID.equals(ssid)) {
                        networkId = network.networkId;
                    }
                } else {
                    String testSSID = network.SSID + this.getSecurityType(network);
                    if(testSSID.equals(ssid + authType)) {
                        networkId = network.networkId;
                    }
                }
            }
        }
        // Fallback to WPA if WPA2 is not found
        if (networkId == -1 && authType.substring(0,3).equals("WPA")) {
            for (WifiConfiguration network : currentNetworks) {
                if (network.SSID != null) {
                    if (authType.length() == 0) {
                        if(network.SSID.equals(ssid)) {
                            networkId = network.networkId;
                        }
                    } else {
                        String testSSID = network.SSID + this.getSecurityType(network).substring(0,3);
                        if(testSSID.equals(ssid + authType)) {
                            networkId = network.networkId;
                        }
                    }
                }
            }
        }
        return networkId;
    }
    }
/**
   * This method retrieves the SSID for the currently connected network
   *
   * @param callbackContext A Cordova callback context
   * @return true if SSID found, false if not.
   */
    private boolean getConnectedSSID(CallbackContext callbackContext) {
        return getWifiServiceInfo(callbackContext, false);
      }

    /**
   * This method retrieves the WifiInformation for the (SSID or BSSID) currently connected network.
   *
   * @param callbackContext A Cordova callback context
   * @param basicIdentifier A flag to get BSSID if true or SSID if false.
   * @return true if SSID found, false if not.
   */
  private boolean getWifiServiceInfo(CallbackContext callbackContext, boolean basicIdentifier) {    

      WifiInfo info = wifiManager.getConnectionInfo();

      if (info == null) {
        callbackContext.error("UNABLE_TO_READ_WIFI_INFO");
          return false;
      }

      // Only return SSID when actually connected to a network
      SupplicantState state = info.getSupplicantState();
      if (!state.equals(SupplicantState.COMPLETED)) {
        callbackContext.error("CONNECTION_NOT_COMPLETED");
          return false;
      }

      String serviceInfo;
      serviceInfo = info.getSSID();

      if (serviceInfo == null || serviceInfo.isEmpty() || serviceInfo == "0x") {
        callbackContext.error("WIFI_INFORMATION_EMPTY");
          return false;
      }

      // http://developer.android.com/reference/android/net/wifi/WifiInfo.html#getSSID()
      if (serviceInfo.startsWith("\"") && serviceInfo.endsWith("\"")) {
          serviceInfo = serviceInfo.substring(1, serviceInfo.length() - 1);
      }
  
      callbackContext.success(serviceInfo);
      return true;
    }
  }


  public void forceWifiUsageQ(CallbackContext callbackContext, boolean useWifi, NetworkRequest networkRequest) {
    if (API_VERSION >= 29) {
        if (useWifi) {
            final ConnectivityManager manager = (ConnectivityManager) this.context
                    .getSystemService(Context.CONNECTIVITY_SERVICE);
            if (networkRequest == null) {
                networkRequest = new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build();
            }

            manager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    manager.bindProcessToNetwork(network);
                    String currentSSID = WifiService.this.getWifiServiceInfo(null);

                    String ssid = callbackContext.getString("ssid");
                    if (currentSSID.equals(ssid)) {
                        WifiService.this.getConnectedSSID(callbackContext);
                    } else {
                        callbackContext.error("CONNECTED_SSID_DOES_NOT_MATCH_REQUESTED_SSID");
                    }
                    WifiService.this.networkCallback = this;
                }
                @Override
                public void onUnavailable() {
                    callbackContext.error("CONNECTION_FAILED");
                }
            });

        } else {
            ConnectivityManager manager = (ConnectivityManager) this.context
                    .getSystemService(Context.CONNECTIVITY_SERVICE);

            if (this.networkCallback != null) {
                manager.unregisterNetworkCallback(this.networkCallback);
                this.networkCallback = null;
            }
            manager.bindProcessToNetwork(null);
        }
    }
    }

}