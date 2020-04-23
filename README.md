# BurpInstaTools

## Features
 - Signed requests are printed as JSON (with signature-key)
 - Urlencoded requests are printed as JSON
 - Responses are prettyprinted (no more JSONBeautifier)
 - Decoding `/logging_client_events` requests
 
## Using
1. Grab the latest [release](https://github.com/Nerixyz/BurpInstaTools/releases).
2. Make sure you're using at least Burp 1.7.22 and Java 11.
3. Go to the `Extender` tab.
4. Click `Add` and add the extension.
5. Now open a request and go to the `Instagram` tab.
 
## TODO
 - Properly add static methods
 - Intercepting and editing requests/responses
 - Better GUI for headers
 - Copying of json (as text, for js and as ts-type)
 
## Building
Run `gradlew fatJar`. 
The resulting jar is in `build/libs/`.
