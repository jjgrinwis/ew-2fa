/*
(c) Copyright 2023 Akamai Technologies, Inc. Licensed under Apache 2 license.
Purpose: limit the number of AIC HostedLogin 2FA retries using EdgeKV
*/
import { logger } from "log";
import { EdgeKV } from "./edgekv.js";

/* 
A "cold-key" edgeKV lookup might take too long so just retry it x times.
Our namespace is in US, try to use the most optimal location EU or Asia for your customers.
We're also setting a global timeout (1-1000) we're going to user for reading and writing.
https://techdocs.akamai.com/edgekv/docs/library-helper-methods#constructor
*/
const edgeKv2fa = new EdgeKV({namespace: "jgrinwiskv",  group: "aic2fa", num_retries_on_timeout:2});
const edgeKvTimeout = 500

/*
let see if we can use some global vars and set them during onClientRequest event.
I don't want to lookup the number of faild attempts and clientIp again.
*/
let trueClientIp: string
let failedAttempts: number = 0

export async function onClientRequest(request: EW.IngressClientRequest) {
    /* 
    In the onClienRequest() eventhandler we're going to check if a client has any previous failed 2FA attempts.
    Any failed attempt will be recorded in EdgeKV in the onOriginResponse() handler.
    For now using the client-ip as the unique key.
    */

    /* 
    asked ChatGPT where to place a const that's only used in a function.
    According to ChatGPT if it's only used in a function just place it there. ;-)
    we're using the value delivered via our delivery configuration but if empty string, null or undefined, set it to X
    */
    const maxNumberOfAttempts = request.getVariable("PMUSER_MAX_2FA_ATTEMPTS") || 3;

    /*
    checked with ChatGPT and let is more common these days compared to var.
    We also set some default values, again some help from ChatGPT
    */
    let clientInfo: any = null

    /*
    looks like there is no true-client-ip in the header and ip info is not part of the request object
    Let's use PMUSER_CLIENT_REAL_IP in the deliver config and using the builtin.AK_CLIENT_REAL_IP value a
    We need to replace '.' with '-' as we can't use . in the EdgeKV key name.
    There should always be a true client ip otherwise lookup will be an empty string, I guess ;-)
    */
    trueClientIp = request.getVariable("PMUSER_CLIENT_REAL_IP").replace(/\./g, "-");
    logger.log(trueClientIp)

    /* 
    now let's lookup information from EdgeKV using this trueClientIp as the key.
    If EdgeKV is not responding quick enough or key doesn't exists just continue.
    A 'Not Found'(404) will return a default value of null. 
    https://techdocs.akamai.com/edgekv/docs/library-helper-methods#getjson   
    */
    try {
       clientInfo = await edgeKv2fa.getJson({ item: trueClientIp, timeout: edgeKvTimeout })
    } catch (error) {
        logger.log("something went wrong: %s", error.toString)
    }

    /*
    if we have some results, overwrite the default value of 0.
    let also check if key exists just in case results are wrong.
    beware that deleting a key from EdgeKV can take some time
    https://techdocs.akamai.com/edgekv/reference/delete-item
    */
    logger.log(JSON.stringify(clientInfo))
    if (clientInfo !== null && clientInfo.hasOwnProperty("failedAttempts")) {
        failedAttempts = clientInfo.failedAttempts
    } 
    logger.log("onClientRequest failed attempts: %d", failedAttempts)

    // return an error if we've hit/crossed the max number of attempts
    if (failedAttempts >=  maxNumberOfAttempts) {
        request.respondWith(403, {'Content-Type': ['application/json;charset=utf-8']}, '{"error": "too many failed 2FA codes"}');
    }
}

export async function onOriginResponse(request: EW.EgressClientRequest, response: EW.EgressOriginResponse) {
    /*
    As the lookup for the IP and attemtps as already happened, just reuse those global vars.
    In case there isn't a 200 OK, flag it as a failed attempt.
    */
    logger.log("response: %d", response.status)

    /*
    only when there is a failed attempt register it by incrementing it with 1
    not doing another lookup, let's use previous value from global namespace.
    I've asked ChatGPT to verify the code and it advised not to use a global var but do the lookup again.
    */
    if (response.status !== 200 ) {
        failedAttempts++
        let attempts = {failedAttempts: failedAttempts}
        logger.log("new failed attempts: %s", JSON.stringify(attempts))

        /*
        lets write this new value into our key value store.
        As we don't readly care about the response, don't wait for it.
        We might want to include a trueClientIp Check in case anything is wrong with it.
        */
        try {
            edgeKv2fa.putJsonNoWait({ item: trueClientIp, value: attempts})
        } catch (error) {
            logger.log("put error: %s", error.toString)
        }
    } else {
        logger.log("2FA code approved")
    }
}