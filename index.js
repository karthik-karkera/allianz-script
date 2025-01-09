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
    const fileName = `${appData.name.replace(/[^a-zA-Z0-9]/g, '_')}.xml`;
    const filePath = path.join(dateFolder, fileName);

    try {
        const url = constants.ASE_GET_HTML_ISSUE_DETAILS.replace("{APPID}", appData.id);
        await downloadFile(url, filePath, token)
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
                        logger.error(err, `App : ${app.name}`)
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
        },
        data: JSON.stringify([
            "severity=high,medium,low,information"
        ])
    };
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const downloadFile = async (url, downloadPath, token) => {
    try {
        const writer = require("fs").createWriteStream(downloadPath);
        var httpOptions = httpASEConfig(token, "POST", url);
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
        console.log(err)
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