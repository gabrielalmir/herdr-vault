// Adapted from herdr-music-mod.
import {randomBytes,createHash} from "crypto";
import {connect} from "net";
import {exec} from "herdr";

const hex = bytes => Array.from(bytes,byte=>byte.toString(16).padStart(2,"0")).join("");
function base64(bytes) {
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result="";
  for(let i=0;i<bytes.length;i+=3) {
    const word=(bytes[i]<<16)|((bytes[i+1]??0)<<8)|(bytes[i+2]??0);
    result+=alphabet[word>>>18]+alphabet[(word>>>12)&63];
    result+=i+1<bytes.length ? alphabet[(word>>>6)&63] : "=";
    result+=i+2<bytes.length ? alphabet[word&63] : "=";
  }
  return result;
}

export async function deriveOnWindows(password,salt,cx,workerPath,operation = { check() {}, wait: work => work }) {
  const challenge=hex(randomBytes(32));
  const entropy=randomBytes(2);
  const port=49152+((entropy[0]*256+entropy[1])%16384);
  const systemRoot=process.env?.SystemRoot || "C:\\Windows";
  const program=systemRoot+"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const failed=exec(program,["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",workerPath,String(port),challenge],{timeout:6000})
    .then(result => {
      if (result.code !== 0) throw Error("Windows vault key derivation failed.");
      return new Promise(() => {});
    }, () => { throw Error("The Windows vault worker could not start."); });
  failed.catch(() => {});
  let socket;
  try {
    for(let tries=0;tries<45;tries++) {
      operation.check();
      try {socket=await connect("127.0.0.1",port);break;}
      catch {await operation.wait(cx.sleep(35));}
    }
    if(!socket) throw Error("The Windows vault worker could not start.");
    operation.check();
    let pending="";
    const line=async()=>{
      while(!pending.includes("\n")) {
        const bytes=await socket.read(128);
        if(!bytes || !bytes.length) throw Error("The Windows vault worker disconnected.");
        pending+=String.fromCharCode(...bytes);
        if(pending.length>256) throw Error("Invalid Windows vault worker reply.");
      }
      const end=pending.indexOf("\n"), value=pending.slice(0,end).trim();
      pending=pending.slice(end+1);
      return value;
    };
    const proof=role=>createHash("sha256").update(role+":"+challenge).digest("hex");
    if(await operation.wait(Promise.race([line(), failed]))!==proof("server")) throw Error("Could not authenticate the Windows vault worker.");
    operation.check();
    await operation.wait(socket.write(proof("client")+"\n"+base64(password)+"\n"+base64(salt)+"\n"));
    const key=await operation.wait(Promise.race([line(), failed]));
    if(!/^[a-f0-9]{64}$/.test(key)) throw Error("Windows vault key derivation failed.");
    operation.check();
    return Uint8Array.from(key.match(/../g),byte=>parseInt(byte,16));
  } finally {
    socket?.close();
  }
}
