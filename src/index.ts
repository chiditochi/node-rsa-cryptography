import * as path from "node:path";
import colors from "colors";
import {
  generatePemFiles,
  getPublicKey,
  encrypt,
  decrypt,
  arcaEncrypt
} 
from "./lib/crypto.js";
//from "./lib/forge.js";

async function encryptData(data: string) {
  //encrypted data
  const encrypted = await encrypt(data);
  console.log(colors.yellow("\nEncrypted data: \n") + colors.bold.gray(encrypted as string));
}

async function decryptData(encrypted: string) {
  //decrypted data ...
  const decrypted = await decrypt(encrypted);
  console.log(colors.yellow("\nDecrypted data: \n") + colors.bold.gray(decrypted as string));
}

async function runProcess () {
  const args = process.argv;
  // actions can be encr or decr
  const action: string = args[2] as string;
  const value: string = args[3] as string;

  console.log(colors.green(`\n\nStarting ... with action = ${action} and value = ${value}\n`));

  if (action === "arca-encr"){
    console.log(colors.yellow(`To Encrypt data: \n` +colors.bgWhite(value)));
    const cipherText = await arcaEncrypt(value);
    console.log(colors.green('Encrypted data: \n') + colors.bold.gray(cipherText as string));
  }
  else if (action === "encr"){
    console.log(colors.yellow(`To Encrypt data: \n` +colors.bold.gray(value)));
    await encryptData(value);
  }
  else if (action === "decr"){
    console.log(colors.yellow(`To Decrypt data: \n` +colors.bold.gray(value)));
    await decryptData(value);
  }
  else if (action === "gene") {
    await generatePemFiles();
    console.log(
      colors.green("Keys: \n") +
        colors.bold.yellow("publicKey,  privateKey and arcaPublicKey generated ...")
    );
  } else if (action === "publicKey") {
    const publicKey = await getPublicKey();
    console.log(colors.green("Public Key: \n") + colors.bold.gray(publicKey));
  }else{
    console.log(colors.bold.yellow("No action specified. Please pick any of the following actions: \n "));
    
    console.log(colors.bold.gray("\tTo generate public and private keys: \n") + colors.green("\tnpm run start gene"));
    console.log(colors.bold.gray("\tTo get public key: \n") + colors.green("\tnpm run start publicKey"));
    console.log(colors.bold.gray("\tTo encrypt data: \n") + colors.green("\tnpm run start encr <text>"));
    console.log(colors.bold.gray("\tTo decrypt data: \n") + colors.green("\tnpm run start decr <encrypted>"));
    console.log(colors.bold.gray("\tTo arca encrypt data: \n") + colors.green("\tnpm run start arca-encr <text>"));
  }

  console.log(colors.bold.green("\n\nDone ..."));
}



runProcess().catch((error) => console.error(colors.bold.red(String(error))));