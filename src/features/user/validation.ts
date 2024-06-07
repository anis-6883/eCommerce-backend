import Joi from "joi";
import { requiredEmailField, requiredStringField, weakPasswordField } from "../../helpers";

export const customerRegisterSchema = Joi.object({
  fullName: requiredStringField("fullName"),
  email: requiredEmailField,
  password: weakPasswordField,
});

export const adminRegisterSchema = Joi.object({
  fullName: requiredStringField("fullName"),
  email: requiredEmailField,
  password: weakPasswordField,
});

export const loginSchema = Joi.object({
  email: requiredEmailField,
  password: weakPasswordField,
});

export const verifyOtpSchema = Joi.object({
  otp: Joi.number().required().integer().min(100000).max(999999).messages({
    "number.base": "otp must be number!",
    "number.integer": "otp must be integer!",
    "number.min": "otp must be 6 digits long!",
    "number.max": "otp must be 6 digits long!",
    "any.required": "otp is required!",
  }),
});
