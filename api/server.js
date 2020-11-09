const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const sessionStore = require("connect-session-knex")(session);
const userRouter = require("../users/user-router");
const Users = require("../users/user-model");

const server = express();

server.use(helmet());
server.use(morgan("dev"));
server.use(express.json());

server.use(
  session({
    name: "monkey",
    secret: "keep it secret, keep it safe",
    cookie: {
      maxAge: 1000 * 60 * 60,
      secure: false,
      httpOnly: true,
    },
    resave: false,
    saveUninitialized: false,
    store: new sessionStore({
      knex: require("../data/config"),
      tablename: "sessions",
      sidfieldname: "sid",
      createTable: true,
      clearInterval: 1000 * 60 * 60,
    }),
  })
);

server.use("/api/users", userRouter);

server.post("/api/register", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    const user = { username, password: hash };
    const newUser = await Users.add(user);
    if (newUser) {
      res.status(201).json(newUser);
    } else {
      next({ code: 400, message: "unable to add new user" });
    }
  } catch (err) {
    next({ code: 500, message: err.message });
  }
});

server.post("api/login", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const user = await Users.findBy({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.status(200).json({ message: `welcome back ${user.username}` });
    } else {
      next({ code: 403, message: "invalid credentials" });
    }
  } catch (err) {
    next({ code: 500, message: err.message });
  }
});

server.use((err, req, res, next) => {
  res.status(err.code).json({ message: err.message });
});
