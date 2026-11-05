(async()=>{
 try{await import('./app.js')}
 catch(error){
  console.error('No se pudo iniciar Tools LatamGCP',error);
  const banner=document.getElementById('banner');
  if(banner){banner.textContent='No se pudo iniciar el panel: '+(error?.message||String(error));banner.className='banner error';banner.hidden=false}
  const status=document.getElementById('savedStatus');if(status)status.textContent='Error de carga';
 }
})();
