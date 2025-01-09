var constants = {
    ASE_API_KEYLOGIN: "/api/keylogin/apikeylogin",
    ASE_SCAN_DETAILS: "/api/jobs/{JOBID}",
    ASE_ISSUES_APPLICATION: "/api/issues?query=Application%20Name%3D{APPNAME}&compactResponse=false",
    ASE_APPLICATION:"/api/applications",
    ASE_APPLICATION_DETAILS: "/api/applications/{APPID}",
    ASE_ISSUE_DETAILS: "/api/issues/{ISSUEID}/application/{APPID}/",
    ASE_UPDATE_ISSUE: "/api/issues/{ISSUEID}/",
    // ASE_GET_HTML_ISSUE_DETAILS: "/api/issues/details_v2?appId={APPID}&ids=[\"{ISSUEID}\"]",
    ASE_GET_HTML_ISSUE_DETAILS: "/api/issues/details_v2/xml?appId={APPID}&trafficCharacterLimit=2000",
    ASE_JOB_SEARCH: "/api/jobs/search",
    LOG_LEVEL: "debug",
	LOG_APPENDER1: "out",
	LOG_APPENDER2: "app",
}

module.exports = Object.freeze( constants );
