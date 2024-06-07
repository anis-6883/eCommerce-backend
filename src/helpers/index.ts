import bcrypt from "bcrypt";
import { Request, Response } from "express";
import Joi from "joi";
import jwt from "jsonwebtoken";
import { APP_SECRET } from "../configs/constants";

export const asyncHandler = (func: any) => async (req: Request, res: Response) => {
  try {
    await func(req, res);
  } catch (err) {
    console.error(err);
    if (err.isJoi) {
      const format: any = {};
      err.details.forEach((detail: any) => {
        format[detail.context.label] = detail.message;
      });
      return apiResponse(res, 400, false, "Invalid Request!", format);
    }
    return apiResponse(res, 400, false, "Server Error!");
  }
};

export const apiResponse = (res: Response, statusCode: number, status: boolean, message: string, data?: any) => {
  return res.status(statusCode).json({ status, message, data });
};

export const emailField = Joi.string().email().trim().messages({
  "string.base": "email must be string!",
  "string.email": "email must be valid format!",
  "string.empty": "email must not be empty!",
});

export const requiredEmailField = emailField.required().messages({
  "any.required": "email is required!",
});

export const requiredStringField = (fieldName: string) =>
  Joi.string()
    .trim()
    .required()
    .messages({
      "any.required": `${fieldName} is required!`,
      "string.base": `${fieldName} must be string!`,
      "string.empty": `${fieldName} must not be empty!`,
    });

export const stringField = (fieldName: string) =>
  Joi.string()
    .trim()
    .messages({
      "string.base": `${fieldName} must be string!`,
      "string.empty": `${fieldName} must not be empty!`,
    });

export const requiredLowercaseStringField = (fieldName: string) =>
  Joi.string()
    .trim()
    .lowercase()
    .required()
    .messages({
      "any.required": `${fieldName} is required!`,
      "string.base": `${fieldName} must be string!`,
      "string.empty": `${fieldName} must not be empty!`,
    });

export const lowercaseStringField = (fieldName: string) =>
  Joi.string()
    .trim()
    .lowercase()
    .messages({
      "string.base": `${fieldName} must be string!`,
      "string.empty": `${fieldName} must not be empty!`,
    });

export const weakPasswordField = Joi.string().required().min(6).messages({
  "any.required": "password is required!",
  "string.base": "password must be string!",
  "min.length": "At least 6 characters long!",
});

export const validateBody = (schema: any, body: Object): Object => {
  const result = schema.validate(body, {
    allowUnknown: true,
    abortEarly: false,
  });

  const format: any = {};

  if (result.error) {
    result.error.details.forEach((detail: any) => {
      format[detail.context.label] = detail.message;
    });
  }

  return format;
};

export const generateSalt = async () => {
  return await bcrypt.genSalt();
};

export const generatePassword = async (password: string, salt: string) => {
  return await bcrypt.hash(password, salt);
};

export const generateSignature = (payload: any, expiresIn: number | string) => {
  return jwt.sign(payload, APP_SECRET, { expiresIn });
};

export const validatePassword = async (enteredPassword: string, savedPassword: string, salt: string) => {
  return (await generatePassword(enteredPassword, salt)) === savedPassword;
};

export const excludeMany = async (array: any[], keys: any[]): Promise<any[]> => {
  let newArray: any[] = [];
  array?.map((item) => {
    const temp: any = { ...item._doc };
    for (let key of keys) {
      delete temp[key];
    }
    newArray.push(temp);
  });
  return newArray;
};

export const exclude = (doc: { [key: string]: any }, keys: any[]) => {
  for (let key of keys) {
    delete doc[key];
  }
  return doc;
};

export const getRandomInteger = (min: number, max: number) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

export const flattenObject = (obj: any, parentKey: string = "", result: any = {}) => {
  for (let key in obj) {
    if (obj.hasOwnProperty(key)) {
      let newKey = parentKey ? `${parentKey}.${key}` : key;
      if (typeof obj[key] === "object" && !Array.isArray(obj[key])) {
        flattenObject(obj[key], newKey, result);
      } else {
        result[newKey] = obj[key];
      }
    }
  }
  return result;
};

export const fileValidation = (
  file: Express.Multer.File,
  size: number = 1024 * 1024,
  types: string[] = ["image/jpeg", "image/png", "image/jpg"]
) => {
  if (file?.size > size) {
    return {
      status: false,
      message: "File size is too large!",
    };
  } else if (!types.includes(file.mimetype)) {
    return {
      status: false,
      message: "Invalid file type!",
    };
  } else {
    return {
      status: true,
      message: "File is valid!",
    };
  }
};

export const makePaginate = (docs: any[], page: number, limit: number, skip: number, total: number) => {
  const hasNext = total > skip + Number(limit);
  const hasPrev = Number(page) > 1;

  return {
    docs,
    page: +page,
    limit: +limit,
    totalPage: Math.ceil(total / Number(limit)),
    totalDocs: total,
    hasNext,
    hasPrev,
  };
};
