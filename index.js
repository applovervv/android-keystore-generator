require("dotenv").config();

const express = require("express");
const { execSync } = require("child_process");
const fs = require("fs");
const cors = require("cors");
const path = require("path");

const axios = require("axios");
const bodyParser = require("body-parser");

const app = express();

var rateLimit = require("express-rate-limit");

app.use(bodyParser.json());
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// Apply to all requests
app.use(
  rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
  })
);

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

function generateApkSigningKey(
  alias,
  keyPassword,
  storePassword,
  keystore,
  validityYears = 25, // 약 10000일을 연으로 변환
  dname
) {
  // 현재 날짜 구하기
  const currentDate = new Date();
  const currentYear = currentDate.getFullYear();

  // 최대 허용 가능한 validityYears 계산 (9999년까지)
  const maxValidityYears = 9999 - currentYear;

  if (validityYears <= 0 || validityYears > maxValidityYears) {
    return {
      success: false,
      message: `Validity period must be between 1 and ${maxValidityYears} years.`,
    };
  }

  if (keyPassword.length < 6) {
    return {
      success: false,
      message: `Key password must be at least 6 characters long.`,
    };
  }

  if (storePassword.length < 6) {
    return {
      success: false,
      message: `Keystore password must be at least 6 characters long.`,
    };
  }

  const tempDir = path.join("/tmp", "sign_key_generator");
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }
  const keystorePath = path.join(tempDir, keystore);

  // 연을 일로 변환 (윤년을 고려하여 365.25를 곱함)
  const validityDays = Math.floor(validityYears * 365.25);

  const dnameString = Object.entries(dname)
    .map(([key, value]) => `${key}=${value}`)
    .join(", ");
  // -storetype PKCS12 \
  // JKS 형식을 명시적으로 지정하고, 키 비밀번호와 저장소 비밀번호를 별도로 사용
  const command = `keytool -genkey -v \
    -keystore ${keystorePath} \
    -alias ${alias} \
    -keyalg RSA \
    -keysize 2048 \
    -validity ${validityDays} \
    -storepass ${storePassword} \
    -keypass ${keyPassword} \
    -dname "${dnameString}" > /dev/null 2>&1 `;

  try {
    execSync(command, { stdio: "inherit" });
    return {
      success: true,
      message: `Keystore successfully created: ${keystorePath}`,
      keystorePath: keystorePath,
    };
  } catch (error) {
    return {
      success: false,
      message: `Error occurred while creating keystore: ${error.message}`,
    };
  }

  //   try {
  //     execSync(command, { stdio: "inherit" });
  //     return {
  //       success: true,
  //       message: `키스토어가 성공적으로 생성되었습니다: ${keystorePath}`,
  //       keystorePath: keystorePath,
  //     };
  //   } catch (error) {
  //     return {
  //       success: false,
  //       message: `키스토어 생성 중 오류 발생: ${error.message}`,
  //     };
  //   }
}

function verifyKeystore(keystore, alias, storePassword) {
  const command = `keytool -list -v -keystore ${keystore} -alias ${alias} -storepass ${storePassword}`;

  try {
    const output = execSync(command, { encoding: "utf-8" });
    return { success: true, message: "키스토어 정보:", info: output };
  } catch (error) {
    return {
      success: false,
      message: `키스토어 확인 중 오류 발생: ${error.message}`,
    };
  }
}

app.use(
  "/generate-key",
  rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
  })
);

app.post("/generate-key", async (req, res) => {
  //   console.log(req.body);
  const recaptchaResponse = req.body["g-recaptcha-response"];

  if (!recaptchaResponse) {
    // console.log("reCAPTCHA token is missing.");
    return res.status(400).json({ message: "reCAPTCHA token is missing." });
  }

  // Send verification request to Google reCAPTCHA API
  const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaResponse}`;

  const recaptchaResult = await axios.post(verificationURL);

  if (!recaptchaResult.data.success) {
    // console.log("reCAPTCHA verification failed.");
    return res.status(400).json({ message: "reCAPTCHA verification failed." });
  }

  const { alias, keyPassword, storePassword, validityDays, dname } = req.body;
  const keystore = `${alias}_keystore.jks`;

  const generateResult = generateApkSigningKey(
    alias,
    keyPassword,
    storePassword,
    keystore,
    validityDays,
    dname
  );

  if (generateResult.success) {
    // const verifyResult = verifyKeystore(
    //   generateResult.keystorePath,
    //   alias,
    //   storePassword
    // );

    res.download(generateResult.keystorePath, keystore, (err) => {
      if (err) {
        console.error("파일 다운로드 중 오류 발생:", err);
      }
      // 파일 전송 후 삭제
      fs.unlink(generateResult.keystorePath, (unlinkErr) => {
        if (unlinkErr) {
          console.error("파일 삭제 중 오류 발생:", unlinkErr);
        }
      });
    });
  } else {
    res.status(500).json(generateResult);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
});
