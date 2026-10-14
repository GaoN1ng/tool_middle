const {sm2}=require('sm-crypto'); module.exports=(x,key)=>sm2.doSignature(JSON.stringify(x),key);
