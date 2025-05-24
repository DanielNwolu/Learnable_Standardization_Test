import * as dotenv from 'dotenv';
import path from 'path';
import Joi from 'joi';

dotenv.config({
  path: path.resolve(__dirname, '../../.env')
});

const envSchema = Joi.object().keys({
  NODE_ENV: Joi.string().valid('production', 'development', 'test').required(),
  PORT: Joi.number().required().default('4000'),
  ACCESS_TOKEN_SECRET: Joi.string().min(8).required(),
  API_V1_STR:Joi.string().required(),
  MONGO_URI:Joi.string().required(),
  GITHUB_REPO_LINK: Joi.string().uri().required(),
  POSTMAN_DOC_LINK: Joi.string().uri().required(),
});

const { value: validatedEnv, error } = envSchema
  .prefs({ errors: { label: 'key' } })
  .validate(process.env, { abortEarly: false, stripUnknown: true });

if (error) {
  throw new Error(
    `Environment variable validation error: \n${error.details
      .map((detail) => detail.message)
      .join('\n')}`
  );
}

const settings = {
  node_env: validatedEnv.NODE_ENV,
  server: {
    port: validatedEnv.PORT,
  },
  jwt: {
    access_token: validatedEnv.ACCESS_TOKEN_SECRET,
    refresh_token: {
      secret: validatedEnv.REFRESH_TOKEN_SECRET,
      expire: validatedEnv.REFRESH_TOKEN_EXPIRE,
      cookie_name: validatedEnv.REFRESH_TOKEN_COOKIE_NAME
    }
  },
  rsa: {
    publicKey: validatedEnv.RSA_PUBLIC_KEY,
    privateKey: validatedEnv.RSA_PRIVATE_KEY,
  },
  api:validatedEnv.API_V1_STR,
  dbUrl:validatedEnv.MONGO_URI,
  githubRepoLink: validatedEnv.GITHUB_REPO_LINK,
  postmanDocLink: validatedEnv.POSTMAN_DOC_LINK,
} as const;

export default settings;