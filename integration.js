const async = require("async");
const config = require("./config/config");
const request = require("request");
const util = require("util");
const url = require("url");
const _ = require("lodash");
const fs = require("fs");
let requestWithDefaults;
const NodeCache = require("node-cache");
const tokenCache = new NodeCache({
  stdTTL: 1000 * 100000,
});

let Logger;
let requestOptions = {};

let domainBlackList = [];
let previousDomainBlackListAsString = "";
let previousDomainRegexAsString = "";
let domainBlacklistRegex = null;

function _setupRegexBlacklists(options) {
  if (
    options.domainBlacklistRegex !== previousDomainRegexAsString &&
    options.domainBlacklistRegex.length === 0
  ) {
    Logger.debug("Removing Domain Blacklist Regex Filtering");
    previousDomainRegexAsString = "";
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug(
        { domainBlacklistRegex: previousDomainRegexAsString },
        "Modifying Domain Blacklist Regex"
      );
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, "i");
    }
  }

  if (
    options.blacklist !== previousDomainBlackListAsString &&
    options.blacklist.length === 0
  ) {
    Logger.debug("Removing Domain Blacklist Filtering");
    previousDomainBlackListAsString = "";
    domainBlackList = null;
  } else {
    if (options.blacklist !== previousDomainBlackListAsString) {
      previousDomainBlackListAsString = options.blacklist;
      Logger.debug(
        { domainBlacklist: previousDomainBlackListAsString },
        "Modifying Domain Blacklist Regex"
      );
      domainBlackList = options.blacklist.split(",").map((item) => item.trim());
    }
  }
}

function _isEntityBlacklisted(entityObj, options) {
  if (domainBlackList.indexOf(entityObj.value) >= 0) {
    return true;
  }

  if (entityObj.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entityObj.value)) {
        Logger.debug(
          { domain: entityObj.value },
          "Blocked BlackListed Domain Lookup"
        );
        return true;
      }
    }
  }

  return false;
}

function getTokenCacheKey(options) {
  return options.clientId + options.clientSecret;
}

function getAuthToken(options, callback) {
  let cacheKey = getTokenCacheKey(options);
  let token = tokenCache.get(cacheKey);

  if (token) {
    callback(null, token);
    return;
  }

  request(
    {
      url: `https://cyberriskanalytics.com/oauth/token`,
      body: {
        grant_type: "client_credentials",
        client_id: options.clientId,
        client_secret: options.clientSecret,
      },
      json: true,
      method: "POST",
    },
    (err, resp, body) => {
      if (err) {
        callback(err);
        return;
      }

      Logger.trace({ body: body }, "Result of token lookup");

      if (resp.statusCode != 200) {
        callback({ err: new Error("status code was not 200"), body: body });
        return;
      }

      tokenCache.set(cacheKey, body.access_token);

      Logger.trace({ tokenCache: tokenCache }, "Checking TokenCache");

      callback(null, body.access_token);
    }
  );
}

function doLookup(entities, options, cb) {
  let results = [];
  Logger.trace("starting lookup");

  Logger.trace("options are", options);

  _setupRegexBlacklists(options);

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error("get token errored", err);
      cb({ err: err });
      return;
    }

    Logger.trace({ token: token }, "what does the token look like in doLookup");

    async.each(
      entities,
      (entityObj, next) => {
        if (_isEntityBlacklisted(entityObj, options)) {
          next(null);
        } else {
          _lookupEntity(entityObj, token, options, function (err, result) {
            if (err) {
              next(err);
            } else {
              results.push(result);
              Logger.debug({ result: result }, "Checking the result values");
              next(null);
            }
          });
        }
      },
      function (err) {
        Logger.trace(
          { results: results },
          "Checking the final results before the callback"
        );
        if (err) return cb(err);
        cb(null, results);
      }
    );
  });
}

function _getUrl(entityObj) {
  let Query = null;
  // map entity object type to the IRIS REST API type
  switch (entityObj.type) {
    case "domain":
      Query = "breaches_by_url?url=";
      break;
    case "email":
      Query = "by_email?emails=";
      break;
  }
  return `https://cyberriskanalytics.com/api/v1/incidents/${Query}${entityObj.value.toLowerCase()}&per_page=20`;
}

function _getRequestOptions(entityObj, options, token) {
  Logger.trace({ token: token }, "Checking Token in request options");
  return {
    uri: _getUrl(entityObj),
    headers: { Authorization: "Bearer " + token },
    method: "GET",
    json: true,
  };
}

function _lookupEntity(entityObj, token, options, cb) {
  Logger.trace({ token: token }, "checking token in lookup entity");

  const requestOptions = _getRequestOptions(entityObj, options, token);

  Logger.trace(
    { requestoptions: requestOptions },
    "Checking the request options coming through"
  );

  requestWithDefaults(requestOptions, function (err, response, body) {
    let errorObject = _isApiError(err, response, body, entityObj.value);
    if (errorObject) {
      cb(errorObject);
      return;
    }

    Logger.trace(
      { response: response },
      "Checking to see what the response is to ensure catching the right errors"
    );

    if (_isLookupMiss(response, body)) {
      return cb(null, {
        entity: entityObj,
        data: null,
      });
    }

    Logger.debug(
      { body: body, entity: entityObj.value },
      "Printing out the results of Body "
    );

    if (_.isNull(body) || _.isEmpty(body)) {
      cb(null, {
        entity: entityObj,
        data: null, // this entity will be cached as a miss
      });
      return;
    }

    if (
      typeof body.total_entries !== "undefined" &&
      (body.total_entries === 0 || _.isEmpty(body.incidents))
    ) {
      cb(null, {
        entity: entityObj,
        data: null, // this entity will be cached as a miss
      });
      return;
    }

    let severity;
    if (entityObj.type === "domain") {
      const severityData = body.incidents.reduce(
        (agg, item) =>
          !_.isEmpty(item.severity_score) ? [...agg, item.severity_score] : agg,
        []
      );
      severity = "Highest Severity Breach Score: " + Math.max(...severityData);
    }

    const emailData = entityObj.type === "email" && body;

    //Logger.trace({emailData:emailData}, "Checking to see if Properties is going through.");

    // The lookup results returned is an array of lookup objects with the following format
    cb(null, {
      // Required: This is the entity object passed into the integration doLookup method
      entity: entityObj,
      // Required: An object containing everything you want passed to the template
      data: {
        // Required: These are the tags that are displayed in your template
        summary: [],
        // Data that you want to pass back to the notification window details block
        details: { body, email: emailData, severity: severity },
      },
    });
  });
}

function _isApiError(err, response, body, entityObj) {
  if (err) {
    return {
      detail: "Error executing HTTP request",
      error: err,
    };
  }

  // Any code that is not 200 and not 404 (missed response) or 400, we treat as an error
  if (![200, 404, 400, 503, 300, 500].includes(response.statusCode)) {
    return _createJsonErrorPayload(
      "Unexpected HTTP Status Code",
      null,
      response.statusCode,
      "1",
      "Unexpected HTTP Status Code",
      {
        err: err,
        body: body,
        entityValue: entityObj,
      }
    );
  } else if (response.statusCode === 500) {
    return _createJsonErrorPayload(
      "Error with Token",
      null,
      response.statusCode,
      "1",
      "ApiKey is incorrect, please contact Risk BAsed Security for further information.",
      {
        err: err,
        body: body,
        entityValue: entityValue,
      }
    );
  }

  return null;
}

function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)],
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: "POOLPARTY_" + code.toString(),
  };

  if (pointer) {
    error.source = {
      pointer: pointer,
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}
function _isLookupMiss(response, body) {
  return (
    response.statusCode === 404 ||
    response.statusCode === 400 ||
    response.statusCode === 503 ||
    response.statusCode === 300 ||
    response.statusCode === 500 ||
    typeof body === "undefined"
  );
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage,
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(
    errors,
    options,
    "clientId",
    "You must provide a Client ID option."
  );
  validateStringOption(
    errors,
    options,
    "clientSecret",
    "You must provide a Client Secret option."
  );

  callback(null, errors);
}

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (
    typeof config.request.cert === "string" &&
    config.request.cert.length > 0
  ) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === "string" && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === "string" &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === "string" && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (
    typeof config.request.proxy === "string" &&
    config.request.proxy.length > 0
  ) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions,
};
