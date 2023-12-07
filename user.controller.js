const { Sequelize } = require("sequelize");
const authService = require("../services/auth.service");
const { HTTP_CODES, ERROR_MESSAGES } = require("../../config/constants");
const env = require("../../config/environment");
const bcryptService = require("../services/bcrypt.service");
const bcrypt = require("bcrypt-nodejs");
const { validationResult } = require("express-validator");
const { response } = require("express");
var requestIP = require("request-ip");
const PublicIp = require("nodejs-publicip");

const { limitMail } = require("../../limitMail");
const jwt = require("jsonwebtoken");
const { sendMail } = require("../../sendMail");

let htmlmail = `
  <table style="border: 1px solid black;">
    <thead>
      <tr>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">Name</th>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">No of Downloads</th>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">IP Address</th>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">Date of Download</th>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">Start of Week</th>
        <th style="border: 1px solid #999;
        padding: 0.5rem;">End of Week</th>
      </tr>
    </thead>
      `;

/*login api will check  the email password and sent store ip address from frontend */

exports.login = async (request, response) => {
  const { body } = request;

  try {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      return response
        .status(HTTP_CODES.BAD_REQUEST)
        .json({ errors: errors.array() });
    }
    const sequelize = new Sequelize(env.development);
    const [results] = await sequelize.query(
      `select * from Users where Email = '${body.email}'`
    );
    // console.log(results);
    if (results.length > 0) {
      const user = results.find((x) => x.Email === body.email);
      if (bcryptService().comparePassword(body.password, user.Password)) {
        user.Password = "";
        const token = { auth: authService().issue({ id: user.User_ID }) };

        async function insertLoginHistoryAndFetchTime() {
          try {
            const IP_Address = request.headers["clientip"];

            console.log(IP_Address);
            const sequelize = new Sequelize(env.development);
            let query = `  INSERT INTO Login_history(User_Id, Login_Time, IP_Address)
              VALUES (${user.User_ID}, UTC_TIMESTAMP(),'${IP_Address}' );`;
            const [insertId] = await sequelize.query(query);
            if (results) {
              let selectquery = ` SELECT Login_Time  from Login_history where Id = ${insertId};`;
              const [[newResult]] = await sequelize.query(selectquery);
            } else {
              response.status(HTTP_CODES.NOT_FOUND).send({
                message: `It seems that there are no users available in the system`,
              });
            }

            const userWithToken = { ...user, ...token };
            response.status(HTTP_CODES.SUCCESS).send({
              message: `Welcome to GTTSi candidate portal, ${user.First_Name} ${user.Last_Name}`,
              user: userWithToken,
            });
          } catch (error) {
            console.log(error);
            response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
              message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
            });
          }
        }
        insertLoginHistoryAndFetchTime();
      } else {
        response.status(HTTP_CODES.BAD_REQUEST).send({
          message: `Incorrect password for user '${body.email}'.`,
        });
      }
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `User with '${body.email}' does not exists.`,
      });
    }
  } catch (error) {
    console.log(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/* change pwd */

exports.encryptedPassword = async (request, response) => {
  const { body } = request;
  try {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      return response
        .status(HTTP_CODES.BAD_REQUEST)
        .json({ errors: errors.array() });
    }
    const sequelize = new Sequelize(env.development);
    const [results] = await sequelize.query(
      `select * from Users where Email = '${body.email}'`
    );
    if (results.length > 0) {
      const user = results.find((x) => x.Email === body.email);

      try {
        const salt = bcrypt.genSaltSync(10);
        console.log(salt);
        const hasedPassword = bcrypt.hashSync(body.password, salt);
        const [updateResult] = await sequelize.query(
          `update Users set password = '${hasedPassword}' where Email = '${body.email}'`
        );
        response.status(HTTP_CODES.SUCCESS).send({
          data: updateResult,
          message: "updated!",
        });
      } catch (error) {
        console.log(error);
      }
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `User with '${body.email}' does not exists.`,
      });
    }
  } catch (error) {
    console.log(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/*count(onclick insert into downlaods table,downloads.userid, check limit, if limit more email) */
exports.resumeDownloadsCounter = async (request, response) => {
  const { body } = request;
  try {
    const tokentemp = request.headers.authorization;
    const token = tokentemp.replace("Bearer ", "");
    const decoded = jwt.decode(token);
    let count = 1;
    const sequelize = new Sequelize(env.development);
    let checkquery = `SELECT * FROM Downloads WHERE User_Id = ${
      decoded.id
    } and Date = "${new Date().toLocaleDateString("en-CA")}"  `;
    const [checkqueryresults] = await sequelize.query(checkquery);

    let limitCheckQuery = `SELECT COUNT(Downloads.User_Id) AS NoOfDownloads
    FROM Downloads
    JOIN Users ON Downloads.User_ID = Users.User_ID
    WHERE Downloads.User_Id = ${
      decoded.id
    } and CAST(Downloads.Date as DATE) = "${new Date().toLocaleDateString(
      "en-CA"
    )}" ;
    `;
    const [limitCheckQueryresults] = await sequelize.query(limitCheckQuery);
    let Download_Limit = `SELECT Download_Limit from Settings `;
    const [Download_Limitresults] = await sequelize.query(Download_Limit);
    console.log(Download_Limitresults[0].Download_Limit);
    if (
      limitCheckQueryresults[0].NoOfDownloads >
      Download_Limitresults[0].Download_Limit
    ) {
      console.log("download completed");
      limitMail();
    }

    let query = `INSERT INTO Downloads(User_ID, Date, Count)
      VALUES (${decoded.id}, now(), ${Number(count)});`;
    const results = await sequelize.query(query);

    // i made a settings table in database which is included Download_Limit ,Name,Id column i want to make condition for where Download_Limit > COUNT(downloads.User_Id)
    if (results) {
      let selectquery = `SELECT count(*) as Count 
                          FROM Downloads 
                          WHERE Date = "${new Date().toLocaleDateString(
                            "en-CA"
                          )}" 
                          AND User_ID = ${decoded.id};`;

      const [[newResult]] = await sequelize.query(selectquery);

      response.status(HTTP_CODES.SUCCESS).send({
        message: `User Downloads fetched successfully !`,
        Count: newResult.Count,
      });
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `It seems that there are no users available in the system`,
      });
    }
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/*  downloads per user on a specific date*/

exports.resumeDownloadsCountSend = async (request, response) => {
  const { body } = request;
  const tokentemp = request.headers.authorization;
  const token = tokentemp?.replace("Bearer ", "");
  const decoded = jwt.decode(token);
  try {
    if (decoded.id) {
      const sequelize = new Sequelize(env.development);
      let selectquery = ` SELECT COUNT(Downloads.User_Id) AS NoOfDownloads
      FROM Downloads
      JOIN Users ON Downloads.User_ID = Users.User_ID
      where  CAST(Downloads.Date as DATE) = "${new Date().toLocaleDateString(
        "en-CA"
      )}" and Users.User_ID = ${decoded.id}
      ;`;
      let Download_Limit = `SELECT Download_Limit from Settings `;
      const [Download_Limitresults] = await sequelize.query(Download_Limit);
  
      const [[newResult]] = await sequelize.query(selectquery);
      if (newResult) {
        console.log("Count", newResult);
        // need to write condition here
        if (newResult.NoOfDownloads >= Download_Limitresults[0]["Download_Limit"]) {
          statusChange = `
              UPDATE Users
              SET Is_Active = 0
              WHERE User_ID = ${decoded.id}
          `;
          await sequelize.query(statusChange); 
        }
        response.status(HTTP_CODES.SUCCESS).send({
          Count: newResult.NoOfDownloads,
          DownloadLimit: Download_Limitresults[0]["Download_Limit"],
        });
      } else {
        response.status(HTTP_CODES.NOT_FOUND).send({
          message: `It seems that there are no users available in the system`,
        });
      }
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `It seems that auth token is not found in the request`,
      });
    }
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/*send frontend login history table */

exports.loginHistory = async (request, response) => {
  const { body } = request;
  console.log("Hiii");

  try {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      return response
        .status(HTTP_CODES.BAD_REQUEST)
        .json({ errors: errors.array() });
    }

    const sequelize = new Sequelize(env.development);

    let subquery = `SELECT  Users.First_Name, Users.Last_Name,Login_history.Login_Time, Login_history.IP_Address, Login_history.Id FROM Login_history
          JOIN Users
          ON Users.User_ID = Login_history.User_ID;`;
    const [newResults] = await sequelize.query(subquery);
    console.log("helllo", newResults);
    response.status(HTTP_CODES.SUCCESS).send({
      message: `User login history fetched successfully !`,
      newResults,
    });
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/*send frontend download activity */

exports.downloadedActivity = async (request, response) => {
  const { body } = request;
  try {
    const sequelize = new Sequelize(env.development);
    let query = `SELECT Downloads.User_ID, MAX(Downloads.Id) AS Id, Users.First_Name, Users.Last_Name, CAST(Downloads.Date as DATE) as Date, COUNT(Downloads.User_Id) AS NoOfDownloads
    FROM Downloads
    JOIN Users ON Downloads.User_ID = Users.User_ID
    GROUP BY Downloads.User_ID, CAST(Downloads.Date as DATE);`;
    const results = await sequelize.query(query);
    if (results) {
      response.status(HTTP_CODES.SUCCESS).send({
        message: `Download history fetched successfully`,
        results: results[0],
        currentSession: 10,
      });
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `It seems that there is no download history available.`,
      });
    }
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/* active/not active users*/

exports.usersStatus = async (request, response) => {
  const { body } = request;
  const tokentemp = request.headers.authorization;
  const token = tokentemp.replace("Bearer ", "");
  const decoded = jwt.decode(token);
  const sequelize = new Sequelize(env.development);
  let query = ``;
  try {

    // 

    if (!isNaN(body.id)) {
      if(body.status) {
        query = `
          UPDATE Users
          SET Is_Active = !Is_Active
          WHERE User_ID = ${body.id}
        `;
      } else {
        query = `
          UPDATE Users
          SET Is_Active = !Is_Active, Extra_Allowed_Date = "${new Date().toLocaleDateString(
            "en-CA"
          )}"
          WHERE User_ID = ${body.id}
        `;
      }
      await sequelize.query(query);
      response.status(200).send({
        message: `User status updated`,
      });
    } else {
      response.status(400).send("User id required.");
      console.log("error in changing status");
    }
  } catch (error) {
    console.log(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

/* sending frontend data email fname lname isactive userid*/

exports.getUsersData = async (request, response) => {
  const { body } = request;

  try {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      return response
        .status(HTTP_CODES.BAD_REQUEST)
        .json({ errors: errors.array() });
    }

    const sequelize = new Sequelize(env.development);

    let getusersquery = `SELECT  User_ID ,First_Name,Last_Name,Email,Is_Active from Users;`;
    const [getUsersData] = await sequelize.query(getusersquery);
    response.status(HTTP_CODES.SUCCESS).send({
      getUsersData,
    });
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.emailNotification = async (request, response) => {
  const { body } = request;
  try {
    const sequelize = new Sequelize(env.development);
    let query = ` select CONCAT(A.First_Name, ' ', A.Last_Name) AS Name, Count(B.count) as count,C.IP_Address AS IPAddress, B.Date,
        DATE_ADD(CURRENT_DATE, INTERVAL 1-DAYOFWEEK(CURRENT_DATE) DAY) AS StartOfWeek,
        DATE_ADD(CURRENT_DATE, INTERVAL 7-DAYOFWEEK(CURRENT_DATE) DAY) AS EndOfWeek
        from Users as A
        left join Downloads as B on B.User_Id = A.User_Id
        left join Login_history as C on C.User_Id = A.User_Id 
        where B.Date <= DATE_ADD(CURRENT_DATE, INTERVAL 7-DAYOFWEEK(CURRENT_DATE) DAY)
        and B.Date > DATE_ADD(CURRENT_DATE, INTERVAL 1-DAYOFWEEK(CURRENT_DATE) DAY)
        group by A.User_Id, C.IP_Address, B.Date;
        `;
    const [results] = await sequelize.query(query);
    console.log("Results", results);
    results.forEach((item) => {
      htmlmail += `<tr>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.Name}</td>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.count}</td>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.IPAddress}</td>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.Date}</td>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.StartOfWeek}</td>
      <td style="border: 1px solid #999;
      padding: 0.5rem;">${item.EndOfWeek}</td>
    </tr>`;
    });
    htmlmail += `
    </table>`
    sendMail(htmlmail);
    if (results) {
      response.status(HTTP_CODES.SUCCESS).send({
        message: `Data fetched`,
        results,
      });
    } else {
      response.status(HTTP_CODES.NOT_FOUND).send({
        message: `It seems no data is available`,
      });
    }
  } catch (error) {
    console.error(error);
    response.status(HTTP_CODES.INTERNAL_SERVER_ERROR).send({
      message: error || ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  }
};
