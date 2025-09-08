# node-rsa-cryptography

### install dependencies
npm i 

### clean run: 
npm run clean

### build app: 
npm run build


### default run: 
npm run start

### generate keys: 
npm run start gene

### get public key: 
npm run start publicKey

### encrypt data: 
npm run start encr 'God is everything and is never late, be still'

### decrypt data: 
npm run start decr 'T6/lKAeYR5b1RfU6wGGfuH2m91Cb1T0hPestxL533x9Og7yWRKzh/xn7tcgJjOTwlsoVKmZyyF5ANzkdJucViVHyyqM/uIMlgdEvHvbmqPLhRwZW38bOrB0nJrC4Bv+bJP3iCvWHFnlep8EXXdul0N03YH0woCkQW86djqYabD4JRTRgL9Uoh9+Vu+tYW0GBzM/l12OamMzcbZ6tdhchHTw5My0zmAAkZ+JeCXg88yY2vIji1MuzNF9khx+J5wjM0LRMZTtrEuvEmOOKRFzPB2QfVyVuykFbCpIGMgGhS1IakTbjPS6v5+OwtcBm3ny++xMfanPnfFip/G9LCnTOtQ=='

### encrypt data with remote public key data: 
npm run start arca-encr 'Thank you for banking with us ...'

### zip project
zip -r node-rsa-cryptography.zip . -x "*node_modules/*" "*node_modules" "*.git/*" "*.git"

### clean dis/ and keys/ foldeers
rm -rf dist/ keys/ node-rsa-cryptography.zip


MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArO0BSmkIMnh+JAaIhWp8
SW68ezm5Xzd17uk9n79XWlPlBF3Vp+s+vGiWkhabzF6SUSchLXXKMNgME60Gooaj
TsExaVpziUJq3y4e9nYoXxgQvkUmBQ5jCG8mzt2w+y+C3Ai5HAj5qYIwJ8dXcp81
IP3defo0FyXLa7O/q6Nt3C80lneT2zFLSKf6bbaHR/Sip6XaKFr6upmg8jlHWQwE
M+psSgO0KqXn1yRy3qJhQvGbpw5me0PtGi+w+TiuKCyerSs143EerOffB9uyY7oa
QRP0mHgt2v9iBof0djVtJvJdVP3cFBQv+ZJjy4brahooCIJq/FqcruJ2dtU1bpi0
tQIDAQAB


XGbF7Afyuc38mhsxEO0hStdTFcQmsAIipXZIxMlc62foj0+Lcvo90w7DKbqqIFqhx
4FwjcS1On5AHgra7kF00+V+j2tUHuwK5qssEmiyeSIaDGYe96PdGGSntXJ575cICt
eDkjdmB6bAJFubqPJ7DDY5QILbt/dYuj+IJ/c7jX3hRgVD71aIUhaTII7iJoZoKgo
uslJEvwEdH8Cct1EkhyAVDKe5nGu6IGj4y+OavNNxqkmzkPJrroSTXtaR6tAkdSqW
m3dl7gty3BUtP166+vAF+Q+JzlMLlfv66KK2zUUO72TTdAf1aD1vVLxMQ3CmllFiw
WAQwbSz0fSGAPo56g==

provide an implementation of decrypt2 that functions same as decrypt

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

export const decrypt2 = async (encryptedData: string) => {
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