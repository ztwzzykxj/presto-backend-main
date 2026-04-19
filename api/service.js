import AsyncLock from "async-lock";
import fs from "fs";
import jwt from "jsonwebtoken";
import { AccessError, InputError } from "./error.js";

const lock = new AsyncLock();

const JWT_SECRET = "llamallamaduck";
const DATABASE_FILE = "./database.json";
const { KV_REST_API_URL, KV_REST_API_TOKEN, USE_VERCEL_KV } = process.env;
/***************************************************************
                       State Management
***************************************************************/

let admins = {};

const update = async (admins) =>
  new Promise((resolve, reject) => {
    lock.acquire("saveData", async () => {
      try {
        if (USE_VERCEL_KV && KV_REST_API_URL && KV_REST_API_TOKEN) {
          // Store to Upstash KV using REST API
          const response = await fetch(`${KV_REST_API_URL}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${KV_REST_API_TOKEN}`,
            },
            body: JSON.stringify(["SET", "admins", JSON.stringify({ admins }), "EX", "86400"]),
          });
          if (!response.ok) {
            const errText = await response.text();
            console.log("KV write error:", errText);
            reject(new Error("Writing to Vercel KV failed"));
          } else {
            resolve();
          }
        } else {
          // Store to local file system
          try {
            fs.writeFileSync(
              DATABASE_FILE,
              JSON.stringify(
                {
                  admins,
                },
                null,
                2
              )
            );
            resolve();
          } catch (fsError) {
            console.log("Local file write error (expected on Vercel):", fsError.message);
            // On Vercel, this will fail but we can still resolve
            // because the function will use in-memory state
            resolve();
          }
        }
      } catch(error) {
        console.log("Update error:", error);
        reject(new Error("Writing to database failed"));
      }
    });
  });

export const save = () => update(admins);
export const reset = () => {
  update({});
  admins = {};
};

try {
  if (USE_VERCEL_KV && KV_REST_API_URL && KV_REST_API_TOKEN) {
    // Setup default admin object in KV DB
    save();

    // Read from Vercel KV using REST API
    fetch(`${KV_REST_API_URL}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${KV_REST_API_TOKEN}`,
      },
      body: JSON.stringify(["GET", "admins"]),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.result) {
          admins = JSON.parse(data.result)["admins"] || {};
        }
      })
      .catch((err) => {
        console.log("KV read error:", err);
      });
  } else {
    // Read from local file
    const data = JSON.parse(fs.readFileSync(DATABASE_FILE));
    admins = data.admins;
  }
} catch(error) {
  console.log("WARNING: No database found, create a new one");
  save();
}

/***************************************************************
                       Helper Functions
***************************************************************/

export const userLock = (callback) =>
  new Promise((resolve, reject) => {
    lock.acquire("userAuthLock", callback(resolve, reject));
  });

/***************************************************************
                       Auth Functions
***************************************************************/

export const getEmailFromAuthorization = (authorization) => {
  try {
    const token = authorization.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    if (!(email in admins)) {
      throw new AccessError("Invalid Token");
    }
    return email;
  } catch(error) {
    throw new AccessError("Invalid token");
  }
};

export const login = (email, password) =>
  userLock((resolve, reject) => {
    if (email in admins) {
      if (admins[email].password === password) {
        resolve(jwt.sign({ email }, JWT_SECRET, { algorithm: "HS256" }));
      }
    }
    reject(new InputError("Invalid username or password"));
  });

export const logout = (email) =>
  userLock((resolve, reject) => {
    admins[email].sessionActive = false;
    resolve();
  });

export const register = (email, password, name) =>
  userLock((resolve, reject) => {
    if (email in admins) {
      return reject(new InputError("Email address already registered"));
    }
    admins[email] = {
      name,
      password,
      store: {},
    };
    const token = jwt.sign({ email }, JWT_SECRET, { algorithm: "HS256" });
    resolve(token);
  });

/***************************************************************
                       Store Functions
***************************************************************/

export const getStore = (email) =>
  userLock((resolve, reject) => {
    resolve(admins[email].store);
  });

export const setStore = (email, store) =>
  userLock((resolve, reject) => {
    admins[email].store = store;
    resolve();
  });
