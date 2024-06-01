import express from "express";

import { ROLE } from "../../../configs/constants";
import { authAndPermissionCheck } from "../../../middlewares/authMiddleware";
import { adminLogin, adminLogout, adminProfile, adminRegistration } from "./controller";

const router = express.Router();

router.post("/auth/register", adminRegistration);
router.post("/auth/login", adminLogin);
router.post("/auth/logout", adminLogout);
router.get("/auth/profile", authAndPermissionCheck(ROLE.ADMIN), adminProfile);

export default router;
