import { findEnv } from "@nick/api-common";
import cors from "cors";
import express from "express";
import jwt from "express-jwt";
import jwksRsa from "jwks-rsa";
const dotenv = require("dotenv");
const jwtAuthz = require("express-jwt-authz");

export function startAuthServer() {
  const app = express();
  dotenv.config({ path: findEnv() });

  if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
    throw "Make sure you have AUTH0_DOMAIN, and AUTH0_AUDIENCE in your .env file";
  }

  const corsOptions = {
    origin: "*" //'http://localhost:3000',
  };

  app.use(cors(corsOptions));

  const checkJwt = jwt({
    // Dynamically provide a signing key based on the [Key ID](https://tools.ietf.org/html/rfc7515#section-4.1.4) header parameter ("kid") and the signing keys provided by the JWKS endpoint.
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    }),

    // Validate the audience and the issuer.
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ["RS256"]
  });

  const checkScopes = jwtAuthz(["read:messages"]);

  app.get("/api/public", function(_, res) {
    res.json({
      message:
        "Hello from a public endpoint! You don't need to be authenticated to see this."
    });
  });

  app.get("/api/private", checkJwt, function(_req, res) {
    res.json({
      message:
        "Hello from a private endpoint! You need to be authenticated to see this."
    });
  });

  app.get("/api/private-scoped", checkJwt, checkScopes, function(_req, res) {
    res.json({
      message:
        "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
    });
  });

  app.use(function(err, _req, res, _next) {
    console.error(err.stack);
    return res.status(err.status).json({ message: err.message });
  });

  app.listen(3010, () => {
    console.info("Listening on http://localhost:3010");
  });
}