import colors from "colors";
import * as path from "node:path";
import * as fs from "node:fs";
import * as fsPromise from "node:fs/promises";
import * as crypto from "node:crypto";
import * as process from "process";

//key file names
const publicFileName = "keys/node-forge/public.pem";
const privateFileName = "keys/node-forge/private.pem";
const arcaPublicFileName = "keys/arca-public-460.pem";

const arcaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhidYZ2wlHLwQw7N+rYfQ2PqWZGWRP18I2ohGIZmP9QHswn0IQleqiV0jeFAQ7aVcK2V5tqBJC6dNgtKZRN5G+Vcyg/kK4p46/Avf9qBnzrnChv8OboWkrl6c+opJfd6cS8oxtDN4Gvst4ElFnlHVGdvdBxrJ4QONU0lJ3DgYDASGQeMeLmRAuZ0g9g7Ez3X1+B7NPxs5C2+bh5awhve3e83/vUtaYnWpdA2nZ8pGxP/CIoNJWCLMuytAprDMdeKCFooNLyxFO+Mck975QwFcxVyhT53199ZrTNG/fEX7wPWV0YoAYeeTWamuiwUM4Lh52G52DMvtuLTlpI/tAyI3MQIDAQAB
-----END PUBLIC KEY-----`;

const directories = ['keys', 'keys/node-forge'];

const generateKeyPair = async () => {
  return new Promise<{ publicKey: string, privateKey: string }>((resolve, reject) => {
    crypto.generateKeyPair('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      }
    }, (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
      } else {
        resolve({ publicKey, privateKey });
      }
    });
  });
};

const writePemFile = async (pemFileData: string, fileName: string) => {
  const filePath = path.resolve(process.cwd(), fileName);
  await fsPromise.writeFile(filePath, pemFileData, { flag: "w+" });
};

const readPemFile = async (fileName: string) => {
  const filePath = path.resolve(process.cwd(), fileName);
  const pemFile = await fsPromise.readFile(filePath, "utf-8");
  return pemFile;
};

export const generatePemFiles = async () => {
  try {
    // Create directories
    for (const dir of directories) {
      const dirPath = path.join(process.cwd(), dir);
      await fs.promises.mkdir(dirPath, { recursive: true });
      console.log(colors.bold.white(`Successfully created directory: ${dirPath}`));
    }

    // Generate and write keys
    const { publicKey, privateKey } = await generateKeyPair();
    await writePemFile(publicKey, publicFileName);
    await writePemFile(privateKey, privateFileName);
    await writePemFile(arcaPublicKey, arcaPublicFileName);
    
    console.log(colors.bold.yellow("done writing pem files to /keys/node-forge/"));
  } catch (error) {
    console.error(colors.bold.red("error writing forge files " + error));
  }
};

export const encrypt = async (data: string) => {
  try {
    const publicKey = await readPemFile(publicFileName);
    const buffer = Buffer.from(data);
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
  } catch (error) {
    console.error(colors.bold.red(String(error)));
    return null;
  }
};

export const arcaEncrypt = async (data: string) => {
  try {
    const publicKey = await readPemFile(arcaPublicFileName);
    const buffer = Buffer.from(data);
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
  } catch (error) {
    console.error(colors.bold.red(error as string));
    return null;
  }
};

export const decrypt = async (encryptedData: string) => {
  try {
    const privateKey = await readPemFile(privateFileName);
    const buffer = Buffer.from(encryptedData, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString();
  } catch (error) {
    console.error(colors.bold.red(error as string));
    return null;
  }
};

export const getPublicKey = async () => {
  const start = "-----BEGIN PUBLIC KEY-----";
  const end = "-----END PUBLIC KEY-----";
  let pubKey = await readPemFile(publicFileName);
  pubKey = pubKey.replace(start, "");
  pubKey = pubKey.replace(end, "");
  pubKey = pubKey.replace(/\r\n|\n|\r/gm, "");
  return pubKey;
};
