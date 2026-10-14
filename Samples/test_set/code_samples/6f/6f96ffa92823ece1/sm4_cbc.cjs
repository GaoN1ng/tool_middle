const {sm4}=require('sm-crypto'); module.exports=m=>sm4.encrypt(m,KEY,{mode:'cbc',iv:IV});
