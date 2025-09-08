
import forge from "node-forge";
import * as fs from "node:fs";
import * as fsPromise from "node:fs/promises";
import path from "node:path";
import colors from "colors";


//key file names
const publicFileName = "keys/node-forge/public.pem";
const privateFileName = "keys/node-forge/private.pem";
const arcaPublicFileName = "keys/arca-public-460.pem";

const arcaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhidYZ2wlHLwQw7N+rYfQ2PqWZGWRP18I2ohGIZmP9QHswn0IQleqiV0jeFAQ7aVcK2V5tqBJC6dNgtKZRN5G+Vcyg/kK4p46/Avf9qBnzrnChv8OboWkrl6c+opJfd6cS8oxtDN4Gvst4ElFnlHVGdvdBxrJ4QONU0lJ3DgYDASGQeMeLmRAuZ0g9g7Ez3X1+B7NPxs5C2+bh5awhve3e83/vUtaYnWpdA2nZ8pGxP/CIoNJWCLMuytAprDMdeKCFooNLyxFO+Mck975QwFcxVyhT53199ZrTNG/fEX7wPWV0YoAYeeTWamuiwUM4Lh52G52DMvtuLTlpI/tAyI3MQIDAQAB
-----END PUBLIC KEY-----`;

const directories = ['keys', 'keys/node-forge'];

// const cwd = getCWD();
// console.log('CWD', cwd);

const pki = forge.pki;
const rsa = pki.rsa;

const getForgeGeneratedKeyPair = async function () {
  let result = null;
  try {
    const keypair = await rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    result = {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
    };
  } catch (error) {
    console.error(colors.red(error as string));
  }
  return result;
};

const getForgeKeys = async () => {
  const keys = await getForgeGeneratedKeyPair();
  if (!keys) throw new Error("Error generating keys");
  // convert a Forge public key to PEM-format in  pkcs8
  const pemPublicKey = pki.publicKeyToPem(keys.publicKey);
  // convert a Forge public key to PEM-format in pkcs1
  const pemPrivateKey = pki.privateKeyToPem(keys.privateKey);
  return {
    pemPrivateKey,
    pemPublicKey,
  };
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
    const { pemPrivateKey, pemPublicKey } = await getForgeKeys();
    //write public key
    const pub = formatKey(pemPublicKey, true);
    await writePemFile(pub, publicFileName);
    const pri = formatKey(pemPrivateKey, true);
    await writePemFile(pri, privateFileName);
    await writePemFile(arcaPublicKey, arcaPublicFileName);

    console.log("done writing pem files to /keys/node-forge/");
  } catch (error) {
    console.error(colors.red("error writing forge files " + error));
  }
};

const formatKey = (pem: string, withHeaders = false) => {
  let result = null;
  let r = "";
  let array = pem.trim().split(/\r?\n/);
  let lastIndex = array.length - 1;
  pem.split(/\r?\n/).forEach(function (line, index) {
    console.log(line);
    if (index !== lastIndex && index !== 0) {
      r += line;
    }
  });
  result = withHeaders ? `${array[0]}\n${r}\n${array[lastIndex]}` : `${r}`;

  return result;
};


export const encrypt = async (data: string) => {
  let result = null;
  try {
    const pem = await readPemFile(publicFileName);
    const publicKey = forge.pki.publicKeyFromPem(pem);
    const encrypted = publicKey.encrypt(data); // Use appropriate padding scheme "RSA-OAEP"

    result = forge.util.encode64(encrypted);
  } catch (error) {
    console.error(colors.red(error as string));
    result = null;
  }
  return result;
};

export const arcaEncrypt = async (data: string) => {
  let result = null;
  try {
    const pem = await readPemFile(arcaPublicFileName);
    
    const publicKey = forge.pki.publicKeyFromPem(pem);
    const encrypted = publicKey.encrypt(data);
    result = forge.util.encode64(encrypted);
  } catch (error) {
    console.error(colors.red(error as string));
    result = null;
  }
  return result;
};

export const decrypt = async (encryptedData: string) => {
  let result = null;
  try {
    const pem = await readPemFile(privateFileName);

    const privateKey = forge.pki.privateKeyFromPem(pem);
    const decrypted = privateKey.decrypt(forge.util.decode64(encryptedData));
    result = decrypted;

  } catch (error) {
    console.error(colors.red(error as string));
    result = null;
  }
  return result;
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
