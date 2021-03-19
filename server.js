const express = require("express");
const jwt = require("jsonwebtoken");
const config = require("./config/auth.config");
const app = express();
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
const dbConfig = require("./config/db.config");
const db = require("./models");
const Role = db.role;
//connect to mongoDB
db.mongoose
  .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Successfully connect to MongoDB");
    initial();
  })
  .catch((err) => {
    console.error("Connection error", err);
    process.exit();
  });
//Hàm initial() cho phép chúng ta thêm dữ liệu 3 roles vào trong cơ sở dữ liệu, nếu trong DB có rồi thì bỏ qua.
function initial() {
  Role.estimatedDocumentCount((err, count) => {
    if (!err && count === 0) {
      new Role({
        name: "user",
      }).save((err) => {
        if (err) {
          console.log("error", err);
        }
        console.log("added 'user' to roles collection");
      });
      new Role({
        name: "moderator",
      }).save((err) => {
        if (err) {
          console.log("error", err);
        }
        console.log("added 'moderator' to roles collection");
      });
      new Role({
        name: "admin",
      }).save((err) => {
        if (err) {
          console.log("error", err);
        }
        console.log("added 'admin' to roles collection");
      });
    }
  });
}

// simple route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to VNTALKING application." });
});
require("./routes/auth.routes")(app);
require("./routes/user.routes")(app);
const User = db.user;
app.get("/verifyToken", function (req, res) {
  var token = req.body.token || req.query.token;
  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.userId = decoded.id;
  });
  User.findById(req.userId).exec((err, userObj) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    } else return res.json({ user: userObj, accessToken: token });
  });
});
var bcrypt = require("bcryptjs");
app.post("/update_password", function (req, res) {
  var token = req.body.token || req.query.token;
  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.userId = decoded.id;
  });
  User.findById(req.userId).exec((err, userObj) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    } else {
      var passwordIsValid = bcrypt.compareSync(
        req.body.oldpassword,
        userObj.password
      );
      if (passwordIsValid) {
        userObj.password = bcrypt.hashSync(req.body.newpassword, 8);
        userObj.save();
        return res.send({ message: "your password has changed successfully" });
      } else
        return res
          .status(402)
          .send({ message: "your password is wrong! Please do it again" });
    }
  });
});
app.post("/delete_user", function (req, res) {
  var token = req.body.token || req.query.token;
  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.adminId = decoded.id;
  });
  User.findById(req.adminId).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }
    Role.find(
      {
        _id: { $in: user.roles },
      },
      (err, roles) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }
        for (let i = 0; i < roles.length; i++) {
          if (roles[i].name === "admin") {
            return;
          }
        }
        res.status(403).send({ message: "Required Admin Role!" });
        return;
      }
    );
  });
  var user_id = req.body.userid || req.query.userid;
  User.findById(user_id).exec((err, userObj) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    } else {
      userObj.remove();
      res.send({ message: "user has been deleted" });
    }
  });
});
app.get("/get_user_infor", function (req, res) {
  var token = req.body.token || req.query.token;
  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.adminId = decoded.id;
  });
  User.findById(req.adminId).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }
    Role.find(
      {
        _id: { $in: user.roles },
      },
      (err, roles) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }
        for (let i = 0; i < roles.length; i++) {
          if (roles[i].name === "admin") {
            return;
          }
        }
        res.status(403).send({ message: "Required Admin Role!" });
        return;
      }
    );
  });
  User.find().exec((err, users) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    } else {
      var userList = [];
      users.forEach(function (user) {
        if (user.roles[0] == "60473be69b14fa27dc1b2370") {
          userList.push({
            id: user._id,
            username: user.username,
            email: user.email,
            role: "user",
          });
        }
        if (user.roles[0] == "60473be69b14fa27dc1b2371") {
          userList.push({
            id: user._id,
            username: user.username,
            email: user.email,
            role: "moderator",
          });
        }
      });
      return res.send(userList);
    }
  });
});
// set port, listen for requests
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
