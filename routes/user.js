const express = require("express");
const router = express.Router();

const Datastore = require("nedb-promise");
let users = new Datastore({ filename: "users.db", autoload: true });

/* 1️⃣ Setup Magic Admin SDK */
const { Magic } = require("@magic-sdk/admin");
const magic = new Magic(process.env.MAGIC_SECRET_KEY);

/* 2️⃣ Implement Auth Strategy */
const passport = require("passport");
const MagicStrategy = require("passport-magic").Strategy;

const strategy = new MagicStrategy(async function(user, done) {
  const userMetadata = await magic.users.getMetadataByIssuer(user.issuer);
  const existingUser = await users.findOne({ issuer: user.issuer });
  if (!existingUser) {
    /* Create new user if doesn't exist */
    return signup(user, userMetadata, done);
  } else {
    /* Login user if otherwise */
    return login(user, done);
  }
});

passport.use(strategy);

/* 3️⃣ Implement Auth Behaviors */

/* Implement User Signup */
const signup = async (user, userMetadata, done) => {
  let newUser = {
    issuer: user.issuer,
    email: userMetadata.email,
    lastLoginAt: user.claim.iat
  };
  await users.insert(newUser);
  return done(null, newUser);
};

/* Implement User Login */
const login = async (user, done) => {
  /* Replay attack protection (https://go.magic.link/replay-attack) */
  if (user.claim.iat <= user.lastLoginAt) {
    return done(null, false, {
      message: `Replay attack detected for user ${user.issuer}}.`
    });
  }
  await users.update(
    { issuer: user.issuer },
    { $set: { lastLoginAt: user.claim.iat } }
  );
  return done(null, user);
};

/* Attach middleware to login endpoint */
router.post("/login", passport.authenticate("magic"), (req, res) => {
  if (req.user) {
      res.status(200).end('User is logged in.');
  } else {
     return res.status(401).end('Could not log user in.');
  }
});

/* 4️⃣ Implement Session Behavior */

/* Defines what data are stored in the user session */
passport.serializeUser((user, done) => {
  done(null, user.issuer);
});

/* Populates user data in the req.user object */
passport.deserializeUser(async (id, done) => {
  try {
    const user = await users.findOne({ issuer: id });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

/* 5️⃣ Implement User Endpoints */

/* Implement Get Data Endpoint */
router.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    return res
      .status(200)
      .json(req.user)
      .end();
  } else {
    return res.status(401).end(`User is not logged in.`);
  }
});

/* Implement Buy Apple Endpoint */
router.post("/buy-apple", async (req, res) => {
  if (req.isAuthenticated()) {
    await users.update(
      { issuer: req.user.issuer },
      { $inc: { appleCount: 1 } }
    );
    return res.status(200).end();
  } else {
    return res.status(401).end(`User is not logged in.`);
  }
});

/* Implement Logout Endpoint */
router.post("/logout", async (req, res) => {
  if (req.isAuthenticated()) {
    await magic.users.logoutByIssuer(req.user.issuer);
    req.logout();
    return res.status(200).end();
  } else {
    return res.status(401).end(`User is not logged in.`);
  }
});

module.exports = router;
