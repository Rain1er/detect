package rain

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

@Suppress("unused")
class Init : BurpExtension {
    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }

        api.extension().setName("detector")
        api.logging().logToOutput("Loading vulnerability Detector")


        // Register the DetectorHttpResponseHandler to handle HTTP responses
        api.proxy().registerRequestHandler(DetectorHttpRequestHandler(api))

        // Register the DetectorHttpResponseHandler to handle HTTP responses
        api.proxy().registerResponseHandler(DetectorHttpResponseHandler(api))
    }
}