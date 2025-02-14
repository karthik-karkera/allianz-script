const express = require('express');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const axios = require('axios').default;
require('dotenv').config();
const constants = require("./utils/constants");
const log4js = require('log4js');
const logger = log4js.getLogger("app");
const https = require('https');
var AdmZip = require("adm-zip");
const unzipper = require('unzipper')

const app = express();
const port = process.env.SECURE_PORT;

var maxLogSize = parseInt(process.env.MAXLOGSIZE);

const reportsDir = path.join(__dirname, 'reports');

log4js.configure({
    appenders: {
        out: { type: 'stdout' },
        app: { type: 'file', filename: process.env.APP_LOG, "maxLogSize": maxLogSize, "numBackups": process.env.NUMBER_OF_BACKUPS }
    },
    categories: {
        default: { appenders: [constants.LOG_APPENDER1, constants.LOG_APPENDER2], level: constants.LOG_LEVEL }
    }
});

if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir);
}

async function aseLogin() {
    try {
        var inputData = {};
        inputData["keyId"] = process.env.keyId;
        inputData["keySecret"] = process.env.keySecret;
        const loginUrl = `${process.env.ASE_URL}${constants.ASE_API_KEYLOGIN}`;
        let result = await axios.post(loginUrl, inputData);
        logger.info('Logged In to ASE');
        return result.data.sessionId;
    } catch (err) {
        throw err;
    }
}

async function fetchApplicationsData(token) {
    try {
        const apiUrl = `${process.env.ASE_URL}${constants.ASE_APPLICATION}`;
        const response = await axios.get(apiUrl, {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': 'asc_session_id=' + token,
                'asc_xsrf_token': token,
                'If-Match': ''
            }
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}

async function generateReport(dateFolder, appData, token) {
    const fileName = `${appData.name.replace(/[^a-zA-Z0-9]/g, '_')}.zip`;
    const filePath = path.join(dateFolder, fileName);

    try {
        const url = `${process.env.ASE_URL}${constants.ASE_REPORTS.replace("{APPID}", appData.id)}`;
        let config = {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': 'asc_session_id=' + token,
                'asc_xsrf_token': token,
                'If-Match': '',
            }
        }

        let data = {
            "config": {
                "executiveSummaryIncluded": true,
                "advisoriesIncluded": true,
                "visitedUrlsIncluded": true,
                "componentGroupsIncluded": true,
                "issueConfig": {
                    "issueAttributeConfig": {
                        "showEmptyValues": false,
                        "attributeLookups": [
                            "applicationname",
                            "cvss",
                            "cvssvector",
                            "cvssversion",
                            "comments",
                            "description",
                            "id",
                            "location",
                            "overdue",
                            "scanname",
                            "scanner",
                            "severityvalue",
                            "status",
                            "datecreated",
                            "fixeddate",
                            "lastupdated",
                            "attackcomplexity",
                            "attackvector",
                            "availabilityimpact",
                            "confidentialityimpact",
                            "exploitcodematurity",
                            "integrityimpact",
                            "privilegesrequired",
                            "remediationlevel",
                            "reportconfidence",
                            "scope",
                            "userinteraction",
                            "api",
                            "branchname",
                            "callingline",
                            "callingmethod",
                            "class",
                            "classification",
                            "commitid",
                            "componentname",
                            "databasename",
                            "databaseservicename",
                            "databasetype",
                            "databaseversion",
                            "discoverymethod",
                            "domain",
                            "element",
                            "externalid",
                            "host",
                            "line",
                            "package",
                            "path",
                            "port",
                            "projectid",
                            "projectname",
                            "projectversion",
                            "projectversionid",
                            "scantype",
                            "scheme",
                            "sourcefile",
                            "third-partyid",
                            "username"
                        ]
                    },
                    "includeAdditionalInfo": false
                },
                "applicationAttributeConfig": {
                    "showEmptyValues": false,
                    "attributeLookups": [
                        "businessimpact",
                        "businessunit",
                        "description",
                        "riskrating",
                        "testingstatus",
                        "criticalissues",
                        "fixedissues",
                        "highissues",
                        "informationissues",
                        "lowissues",
                        "mediumissues",
                        "overdueissues",
                        "totalissues"
                    ]
                },
                "pdfPageBreakOnIssue": false,
                "sortByURL": false
            },
            "layout": {
                "reportOptionLayoutCoverPage": {
                    "companyLogo": "",
                    "additionalLogo": "",
                    "includeDate": true,
                    "includeReportType": true,
                    "reportTitle": "Application Report",
                    "description": "This report includes important security information about your application."
                },
                "reportOptionLayoutBody": {
                    "header": "",
                    "footer": ""
                },
                "includeTableOfContents": true
            },
            "reportFileType": "XML",
            "issueIdsAndQueries": [
                "status=open,status=inprogress,status=reopened,status=passed,status=fixed,status=new,classification=definitive,classification=suspect,severity=information",
                "status=open,status=inprogress,status=reopened,status=passed,status=fixed,status=new,classification=definitive,classification=suspect,severity=low",
                "status=open,status=inprogress,status=reopened,status=passed,status=fixed,status=new,classification=definitive,classification=suspect,severity=medium",
                "status=open,status=inprogress,status=reopened,status=passed,status=fixed,status=new,classification=definitive,classification=suspect,severity=high",
                "status=open,status=inprogress,status=reopened,status=passed,status=fixed,status=new,classification=definitive,classification=suspect,severity=critical"
            ]
        }

        let result = await axios.post(url, data, config);
        let reportId = result.data.split(": ")[1];
        await delay(25000)
        let reportDownloadUrl = constants.ASE_REPORTS_DOWNLOAD.replace('${reportId}', reportId)
        let tempFilePath = path.join(dateFolder, `${reportId}.zip`);

        await downloadFile(reportDownloadUrl, tempFilePath, token)
        await delay(2000)

        await fs.createReadStream(tempFilePath)
            .pipe(unzipper.Extract({ path: dateFolder }))
            .on('close', () => {
                fs.unlinkSync(tempFilePath); // Clean up temporary ZIP file
            })
            .on('error', (err) => {
                console.error('Error extracting ZIP file:', err);
            });
    } catch (err) {
        throw err;
    }
}

async function generateDailyReports() {
    try {
        let token = await aseLogin();
        const applications = await fetchApplicationsData(token);
        await delay(300)
        const dateFolderName = `${new Date().toISOString().split('T')[0]} (${Date.now()})`
        let reportsFolder = path.join(reportsDir, 'reports');
        const dateFolder = path.join(reportsDir, dateFolderName);

        if (fs.existsSync(reportsFolder)) {   //Reports folder exists
            if (!fs.existsSync(dateFolder)) {
                fs.renameSync(reportsFolder, dateFolder);
                if (!fs.existsSync(reportsFolder)) {
                    fs.mkdirSync(reportsFolder);
                }
                for (let app of applications) {
                    try {
                        await generateReport(reportsFolder, app, token);
                        logger.info(`Report added for App: ${app.name}`)
                    } catch (err) {
                        logger.error(err.message, `App : ${app.name}`)
                    }
                }
            } else {
                fs.rmdirSync(dateFolder, {recursive: true});
                fs.renameSync(reportsFolder, dateFolder);
                if (!fs.existsSync(reportsFolder)) {
                    fs.mkdirSync(reportsFolder);
                }
                for (let app of applications) {
                    try {
                        await generateReport(reportsFolder, app, token)
                        logger.info(`Report added for App: ${app.name}`)
                    } catch (err) {
                        logger.error(err, `App : ${app.name}`)
                    }
                }
            }

        } else {                              //Reports folder doesnot exists

            if (!fs.existsSync(reportsFolder)) {
                fs.mkdirSync(reportsFolder);
            }
            for (let app of applications) {
                try {
                    await generateReport(reportsFolder, app, token);
                    logger.info(`Report added for App: ${app.name}`)
                } catch (err) {
                    logger.error(err, `App : ${app.name}`)
                }
            }
        }



        logger.info('Report Generation Completed')
    } catch (error) {
        logger.error(`Error generating daily reports: ${error.message}`)
    }
}

httpASEConfig = function (token, method, url) {
    return {
        method: method,
        url: `${process.env.ASE_URL}${url}`,
        headers: {
            'Content-Type': 'application/json',
            'Cookie': 'asc_session_id=' + token,
            'asc_xsrf_token': token,
            'If-Match': ''
        }
    };
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const downloadFile = async (url, downloadPath, token) => {
    try {
        const writer = require("fs").createWriteStream(downloadPath);
        var httpOptions = httpASEConfig(token, "GET", url);
        httpOptions["responseType"] = 'stream';

        await axios(httpOptions).then(response => {
            return new Promise((resolve, reject) => {
                response.data.pipe(writer);
                let error = null;
                writer.on('error', err => {
                    error = err;
                    writer.close();
                    reject(err);
                });
                writer.on('close', () => {
                    if (!error) {
                        resolve(true);
                    }
                });
            });
        });

    } catch (err) {
        logger.error(err.message)
    }
}

// Schedule the task to run
cron.schedule(process.env.interval, () => {
    console.log('Fetching AppScan data and generating reports...');
    generateDailyReports();
});

generateDailyReports();

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('Daily reports will be saved in the "reports" folder.');
});