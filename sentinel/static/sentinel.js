// -- State --
const MAX=60;
let rpsHist=[],atkHist=[];
let lastPayload=null;
let focusIp='';
let focusHost='';
let focusRef='';
let pollMs=1500;
let pollTimer=null;
let paused=false;
let lastLoadMs=0;
let prevKpi={rps:0,peak:0,uniq:0,errpct:0,atk:0};
let knownAlertCount=0;
let newAlertsSinceBlur=0;
let isPageVisible=true;
let sidebarOpen=true;
let worldMap=null;
let countryHitsMap={};
let mapHoverCode='';
let mapHoverPos={x:0,y:0};
let mapHoverPoll=null;
let seenAlertKeys=new Set();
let bnCampaignMap={};
let modalIp='';
let historyRangeSec=2592000;
let historyMode=false;
let historyPoints=[];
let historyPage=1;
let historyTotal=0;
let historySelectedDay='';
let historyDaysLoaded=false;
let currentBannedSet=new Set();

/* Tab visibility for alert count */
document.addEventListener('visibilitychange',function(){
  if(!document.hidden){
    isPageVisible=true;
    newAlertsSinceBlur=0;
    document.title='Sentinel | SOC';
  }else{
    isPageVisible=false;
  }
});

// -- Live ticker --
setInterval(function(){
  if(!lastLoadMs) return;
  var s=Math.floor((Date.now()-lastLoadMs)/1000);
  var el=document.getElementById('updatedAgo');
  var dot=document.getElementById('liveDot');
  if(s<=2){el.textContent='live';el.style.color='var(--ok)';dot.className='live-dot';}
  else if(s<=8){el.textContent=s+'s ago';el.style.color='var(--ok)';dot.className='live-dot';}
  else{el.textContent=s+'s ago';el.style.color='var(--warn)';dot.className='live-dot stale';}
},1000);

// -- Gradient helper --
function makeGrad(ctx,chart,colorTop,colorBot){
  var ca=chart.chartArea;
  if(!ca) return colorTop;
  var g=ctx.createLinearGradient(0,ca.top,0,ca.bottom);
  g.addColorStop(0,colorTop); g.addColorStop(1,colorBot); return g;
}

// -- Combo chart --
var hasChartJs=(typeof Chart==='function');
if(!hasChartJs){
  var comboCanvas=document.getElementById('comboChart');
  if(comboCanvas) comboCanvas.title='Chart.js unavailable (blocked by browser/privacy settings)';
  var donutCanvas=document.getElementById('statusDonut');
  if(donutCanvas) donutCanvas.title='Chart.js unavailable (blocked by browser/privacy settings)';
}
const comboChart=hasChartJs?new Chart(document.getElementById('comboChart'),{
  type:'line',
  data:{labels:[],datasets:[
    {label:'RPS',data:[],borderColor:'#00d4ff',borderWidth:1.5,
     backgroundColor:function(ctx){return makeGrad(ctx.chart.ctx,ctx.chart,'rgba(0,212,255,0.28)','rgba(0,212,255,0)');},
     fill:true,tension:0.4,pointRadius:0,yAxisID:'y'},
    {label:'Susp/s',data:[],borderColor:'#f87171',borderWidth:1.5,
     backgroundColor:function(ctx){return makeGrad(ctx.chart.ctx,ctx.chart,'rgba(248,113,113,0.2)','rgba(248,113,113,0)');},
     fill:true,tension:0.4,pointRadius:0,yAxisID:'y2'}
  ]},
  options:{responsive:true,maintainAspectRatio:false,
    interaction:{mode:'index',intersect:false},
    plugins:{
      legend:{display:true,position:'top',align:'end',
        labels:{color:'#64748b',boxWidth:10,font:{size:9,family:"'JetBrains Mono',monospace"},padding:8}},
      tooltip:{backgroundColor:'rgba(10,16,28,0.95)',borderColor:'rgba(0,212,255,0.2)',borderWidth:1,
        titleColor:'#94a3b8',bodyColor:'#e2e8f0',padding:8,cornerRadius:7,
        titleFont:{family:"'JetBrains Mono',monospace",size:10},
        bodyFont:{family:"'JetBrains Mono',monospace",size:11}}},
    scales:{
      x:{display:false,grid:{display:false}},
      y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#4a5568',font:{size:9}},
         title:{display:true,text:'RPS',color:'#4a5568',font:{size:9}}},
      y2:{beginAtZero:true,position:'right',grid:{display:false},ticks:{color:'#f87171',font:{size:9}},
          title:{display:true,text:'Susp/s',color:'#f87171',font:{size:9}}}}}
}):{data:{labels:[],datasets:[{data:[]},{data:[]}]},update:function(){}};

const statusDonut=hasChartJs?new Chart(document.getElementById('statusDonut'),{
  type:'doughnut',
  data:{labels:['2xx','3xx','4xx','5xx','other'],
    datasets:[{data:[0,0,0,0,0],
      backgroundColor:['#22c55e','#00d4ff','#f59e0b','#ef4444','#4a5568'],
      borderWidth:0,spacing:2,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{
      legend:{position:'bottom',labels:{color:'#64748b',boxWidth:9,font:{size:9},padding:6}},
      tooltip:{backgroundColor:'rgba(10,16,28,0.95)',borderColor:'rgba(0,212,255,0.2)',borderWidth:1,
        titleColor:'#94a3b8',bodyColor:'#e2e8f0',padding:8,cornerRadius:7,
        titleFont:{family:"'JetBrains Mono',monospace",size:10},
        bodyFont:{family:"'JetBrains Mono',monospace",size:11},
        callbacks:{label:function(c){
          var sum=c.dataset.data.reduce(function(a,b){return a+b;},0)||1;
          return c.label+': '+c.raw+' ('+((c.raw/sum)*100).toFixed(1)+'%)';
        }}}}}
}):{data:{datasets:[{data:[0,0,0,0,0]}]},update:function(){}};

// -- World map --
function initWorldMap(){
  if(worldMap||typeof jsVectorMap==='undefined') return;
  function regionCodeFromTarget(t){
    if(!t) return '';
    var el=t.closest ? t.closest('path, g, [data-code], [data-region], [id]') : t;
    if(!el) return '';
    var direct=(el.getAttribute && (el.getAttribute('data-code') || el.getAttribute('data-region'))) || '';
    direct=String(direct).trim().toUpperCase();
    if(/^[A-Z]{2}$/.test(direct)) return direct;
    if(el.dataset){
      var ds=(el.dataset.code || el.dataset.region || '').toString().trim().toUpperCase();
      if(/^[A-Z]{2}$/.test(ds)) return ds;
    }
    var attrs=['data-code','data-region','data-name','name','id'];
    for(var i=0;i<attrs.length;i++){
      var raw=(el.getAttribute && el.getAttribute(attrs[i])) || '';
      var m=String(raw).toUpperCase().match(/\b[A-Z]{2}\b/);
      if(m) return m[0];
    }
    return '';
  }
  function mapTooltipMessage(code){
    var cc=String(code||'').toUpperCase();
    if(!cc || cc==='UNDEFINED') cc='??';
    var hits=countryHitsMap[cc]||0;
    return cc+' \u2014 '+hits+' hits';
  }
  function applyMapTooltip(tooltip,msg){
    try{
      if(!tooltip) return;
      if(typeof tooltip.html==='function'){
        try{ tooltip.html(msg,true); }catch(_e1){ try{ tooltip.html(msg); }catch(_e2){} }
      }
      if(typeof tooltip.text==='function'){
        try{ tooltip.text(msg,true); }catch(_e3){ try{ tooltip.text(msg); }catch(_e4){} }
      }
      if(typeof tooltip.setText==='function'){
        try{ tooltip.setText(msg); }catch(_e5){}
      }
      var candidates=[
        tooltip,
        tooltip.element,
        tooltip._tooltip,
        tooltip.selector,
        tooltip.container,
        tooltip.node,
        tooltip[0]
      ];
      candidates.forEach(function(el){
        try{
          if(!el) return;
          if(typeof el.innerHTML!=='undefined') el.innerHTML=msg;
          if(typeof el.textContent!=='undefined') el.textContent=msg;
        }catch(_e6){}
      });
    }catch(_e){}
  }
  function mapTip(msg,x,y){
    var tip=document.getElementById('mapHoverTip');
    var readout=document.getElementById('mapHoverReadout');
    if(!tip) return;
    tip.textContent=msg;
    tip.style.display='block';
    tip.style.left=Math.max(6,(x||0))+'px';
    tip.style.top=Math.max(6,(y||0))+'px';
    if(readout) readout.textContent='Hover country: '+msg;
  }
  function hideMapTip(){
    var tip=document.getElementById('mapHoverTip');
    var readout=document.getElementById('mapHoverReadout');
    if(tip) tip.style.display='none';
    if(readout) readout.textContent='Hover country: \u2014';
  }
  function hoveredRegionCode(mapEl){
    if(!mapEl) return '';
    var el=mapEl.querySelector('.jvm-region:hover,[data-code]:hover,[data-region]:hover,path:hover');
    return regionCodeFromTarget(el);
  }
  try{
    worldMap=new jsVectorMap({
      selector:'#worldMap',map:'world',
      backgroundColor:'transparent',zoomOnScroll:false,
      regionTooltip:false,
      regionStyle:{
        initial:{fill:'#1a2e47',stroke:'#0a1421',strokeWidth:0.45,fillOpacity:0.95},
        hover:{fill:'#2c4f74',cursor:'pointer'}
      },
      onRegionTooltipShow:function(e,tooltip,code){ applyMapTooltip(tooltip,mapTooltipMessage(code)); },
      onRegionTipShow:function(e,tooltip,code){ applyMapTooltip(tooltip,mapTooltipMessage(code)); },
      onRegionOver:function(e,code){
        mapHoverCode=String(code||'').toUpperCase();
        mapTip(mapTooltipMessage(mapHoverCode),e.clientX||0,e.clientY||0);
      },
      onRegionOut:function(){
        mapHoverCode='';
        hideMapTip();
      },
      series:{regions:[{
        attribute:'fill',
        scale:{
          1:'#1e3a8a', /* low */
          2:'#0ea5e9', /* medium */
          3:'#06b6d4', /* high */
          4:'#67e8f9'  /* very high */
        },
        normalizeFunction:'linear',
        values:{}
      }]}
    });
    var mapEl=document.getElementById('worldMapWrap');
    if(mapEl){
      if(mapHoverPoll) clearInterval(mapHoverPoll);
      mapHoverPoll=setInterval(function(){
        var cc=hoveredRegionCode(mapEl);
        if(!cc){
          if(!mapHoverCode) return;
          mapHoverCode='';
          hideMapTip();
          return;
        }
        mapHoverCode=cc;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x||0,mapHoverPos.y||0);
      },120);
      mapEl.addEventListener('mousemove',function(e){
        mapHoverPos.x=e.clientX||0;
        mapHoverPos.y=e.clientY||0;
        var ccByHover=hoveredRegionCode(mapEl);
        if(ccByHover){
          mapHoverCode=ccByHover;
          try{
            var p=e.target && e.target.closest ? e.target.closest('.jvm-region,path') : null;
            if(p && p.setAttribute) p.setAttribute('title',mapTooltipMessage(mapHoverCode));
          }catch(_e0){}
          mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
          return;
        }
        var cc=regionCodeFromTarget(e.target);
        if(cc){
          mapHoverCode=cc;
          try{
            var p2=e.target && e.target.closest ? e.target.closest('.jvm-region,path') : null;
            if(p2 && p2.setAttribute) p2.setAttribute('title',mapTooltipMessage(mapHoverCode));
          }catch(_e1){}
          mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
          return;
        }
        if(!mapHoverCode) return;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
      });
      mapEl.addEventListener('mouseleave',function(){ mapHoverCode=''; hideMapTip(); });
      mapEl.addEventListener('mouseover',function(e){
        var cc=regionCodeFromTarget(e.target);
        if(!cc) return;
        mapHoverCode=cc;
        mapHoverPos.x=e.clientX||0;
        mapHoverPos.y=e.clientY||0;
        mapTip(mapTooltipMessage(mapHoverCode),mapHoverPos.x,mapHoverPos.y);
      });
      mapEl.addEventListener('mouseout',function(e){
        var toEl=e.relatedTarget;
        if(toEl && mapEl.contains(toEl)) return;
        mapHoverCode='';
        hideMapTip();
      });
    }
  }catch(e){
    document.getElementById('worldMapWrap').innerHTML='<div style="color:var(--muted);text-align:center;padding:80px 0;font-family:var(--mono);font-size:12px">Map unavailable (CDN)</div>';
  }
}
function updateWorldMap(countries){
  if(!worldMap) return;
  try{
    var vals={};
    countryHitsMap={};
    (countries||[]).forEach(function(p){
      var cc=String(p[0]||'').toUpperCase();
      var n=Math.max(0,+p[1]||0);
      if(!cc||cc.length!==2||n<=0) return;
      countryHitsMap[cc]=n;
      var bucket=1;
      if(n>=1000) bucket=4;
      else if(n>=200) bucket=3;
      else if(n>=25) bucket=2;
      vals[cc]=bucket;
    });
    worldMap.series.regions[0].setValues(vals);
  }catch(e){}
}

function historyRangeBounds(){
  if(historySelectedDay){
    var start=Date.parse(historySelectedDay+'T00:00:00Z');
    if(!isNaN(start)){
      var from=Math.floor(start/1000);
      return {from:from,to:from+86400-1};
    }
  }
  var to=Math.floor(Date.now()/1000);
  return {from:Math.max(0,to-historyRangeSec),to:to};
}

function applyHistoryChart(points){
  historyPoints=points||[];
  if(!historyMode||!historyPoints.length) return;
  var labels=historyPoints.map(function(p){
    try{return new Date((p.ts||0)*1000).toISOString().slice(11,16);}catch(e){return '';}
  });
  comboChart.data.labels=labels;
  comboChart.data.datasets[0].data=historyPoints.map(function(p){return p.total||0;});
  comboChart.data.datasets[1].data=historyPoints.map(function(p){return p.attacks||0;});
  comboChart.update('none');
}

async function loadHistorySeries(){
  var b=historyRangeBounds();
  var bucket=historySelectedDay?'minute':(historyRangeSec>172800?'hour':'minute');
  try{
    var q='/api/history/series?from='+b.from+'&to='+b.to+'&bucket='+bucket;
    if(historySelectedDay) q+='&day='+encodeURIComponent(historySelectedDay);
    var r=await fetch(q,{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok) return;
    historyPoints=j.points||[];
    if(historyMode) applyHistoryChart(historyPoints);
    var sumT=0,sumA=0,sum4=0,sum5=0;
    historyPoints.forEach(function(p){sumT+=(p.total||0);sumA+=(p.attacks||0);sum4+=(p.client_errors||0);sum5+=(p.server_errors||0);});
    var modeLabel=historySelectedDay?('Day '+historySelectedDay):('Range '+(historyRangeSec/86400).toFixed(0)+'d');
    document.getElementById('historyMeta').innerText=modeLabel+' | points '+historyPoints.length+' | total '+sumT+' | suspicious '+sumA+' | 4xx '+sum4+' | 5xx '+sum5;
  }catch(e){}
}

function renderHistoryEvents(rows){
  var el=document.getElementById('historyRows');
  var arr=rows||[];
  if(!arr.length){
    el.innerHTML='<tr><td colspan="6" style="padding:10px;color:var(--muted);text-align:center">No historical events in selected range</td></tr>';
    return;
  }
  var S='padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05)';
  el.innerHTML=arr.map(function(r){
    var hostHl=(focusHost&&r.host&&r.host.toLowerCase()===focusHost.toLowerCase());
    var hostCell=r.host
      ?'<span class="hist-host-link" data-host="'+escapeAttr(r.host)+'" style="color:'+(hostHl?'var(--warn)':'var(--accent2,#a78bfa)')+';cursor:pointer;text-decoration:underline;text-decoration-style:dotted" title="Filter by host: '+escapeAttr(r.host)+'">'+escapeHtml(r.host)+'</span>'
      :'';
    return '<tr>'
      +'<td style="'+S+'">'+escapeHtml(r.ts||'')+'</td>'
      +'<td style="'+S+';text-align:right"><span class="hist-ip-link" data-ip="'+escapeAttr(r.ip||'')+'" style="color:var(--accent);cursor:pointer;font-weight:700" title="Click to drill down">'+escapeHtml(r.ip||'')+'</span></td>'
      +'<td style="'+S+'" title="'+escapeAttr(r.host||'')+'">'+hostCell+'</td>'
      +'<td style="'+S+'" title="'+escapeAttr(r.path||'')+'">'+escapeHtml(r.path||'')+'</td>'
      +'<td style="'+S+';text-align:right">'+(r.status||0)+'</td>'
      +'<td style="'+S+';text-align:right">'+(r.score||0)+'</td>'
      +'</tr>';
  }).join('');
}

async function loadHistoryEvents(){
  var b=historyRangeBounds();
  try{
    var q='/api/history/events?from='+b.from+'&to='+b.to+'&page='+historyPage+'&page_size=50';
    if(historySelectedDay) q+='&day='+encodeURIComponent(historySelectedDay);
    if(focusIp) q+='&ip='+encodeURIComponent(focusIp);
    if(focusHost) q+='&host='+encodeURIComponent(focusHost);
    if(focusRef) q+='&ref='+encodeURIComponent(focusRef);
    var r=await fetch(q,{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok){renderHistoryEvents([]);return;}
    historyTotal=j.total||0;
    renderHistoryEvents(j.rows||[]);
  }catch(e){
    renderHistoryEvents([]);
  }
}

async function refreshHistory(){
  if(!historyDaysLoaded) await loadHistoryDays();
  await loadHistorySeries();
  await loadHistoryEvents();
}

async function loadHistoryDays(){
  try{
    var r=await fetch('/api/history/days',{credentials:'same-origin'});
    var j=await r.json();
    if(!r.ok||!j.ok) return;
    var sel=document.getElementById('histDaySelect');
    var keep=historySelectedDay;
    sel.innerHTML='<option value="">Range mode</option>';
    (j.days||[]).forEach(function(d){
      var o=document.createElement('option');
      o.value=d.day;
      o.textContent=d.day+'  ('+(d.total||0)+' req)';
      sel.appendChild(o);
    });
    if(keep && (j.days||[]).some(function(d){return d.day===keep;})){
      sel.value=keep;
      historySelectedDay=keep;
    }else{
      historySelectedDay='';
      sel.value='';
    }
    historyDaysLoaded=true;
  }catch(e){}
}

/* Helpers */
function fmtBytes(n){
  if(n===undefined||n===null) return '0 B';
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(1)+' MB';
  if(n<1099511627776) return (n/1073741824).toFixed(2)+' GB';
  return (n/1099511627776).toFixed(2)+' TB';
}
function escapeHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escapeAttr(s){ return escapeHtml(s).replace(/'/g,'&#39;'); }

function timeAgo(ts){
  if(!ts) return '';
  const d=Date.now()-new Date(ts).getTime();
  if(d<5000) return 'just now';
  if(d<60000) return Math.floor(d/1000)+'s ago';
  if(d<3600000) return Math.floor(d/60000)+'m ago';
  return Math.floor(d/3600000)+'h ago';
}

function ccFlag(cc){
  if(!cc||cc.length!==2) return '';
  try{
    return cc.toUpperCase().split('').map(function(c){
      return String.fromCodePoint(0x1F1E6+c.charCodeAt(0)-65);
    }).join('');
  }catch(e){ return ''; }
}

function scorePillCls(n){ if(n>=10) return 'hi'; if(n>=5) return 'med'; return 'lo'; }

function filterPairs(pairs,q){
  var a=pairs||[];
  if(q&&q.trim()){ var t=q.toLowerCase(); a=a.filter(function(p){ return String(p[0]).toLowerCase().includes(t); }); }
  return a;
}

function listRow(rank,key,val,barPct,pct,opts){
  /* opts: {danger,warn,ok,ipClick,tags,bgCls,keyWrap} */
  opts=opts||{};
  var hl=(focusIp&&String(key)===focusIp)?' hl-focus':'';
  var ipCls=opts.ipClick?' row-ip':'';
  var dataIp=opts.ipClick?' data-ip="'+escapeAttr(key)+'"':'';
  var valCls=opts.danger?' danger':opts.warn?' warn':opts.ok?' ok':'';
  var bgCls=opts.bgCls?(' '+opts.bgCls):'';
  var rankCls=rank===1?' r1':'';
  var keyWrap=opts.keyWrap?' wrap':'';
  var pills=(opts.ipClick&&opts.tags&&opts.tags.length)
    ? ' '+opts.tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join('')
    : '';
  var pctHtml=pct!=null?('<span class="list-pct">'+pct+'</span>'):'';
  return '<div class="list-row'+hl+ipCls+'"'+dataIp+'>'
    +'<div class="list-row-bg'+bgCls+'" style="width:'+barPct+'%"></div>'
    +'<span class="list-rank'+rankCls+'">'+rank+'</span>'
    +'<span class="list-key'+keyWrap+'" title="'+escapeAttr(key)+'">'+escapeHtml(key)+pills+'</span>'
    +'<span class="list-val'+valCls+'">'+val+'</span>'
    +pctHtml
    +'</div>';
}

// -- DEFCON posture --
var DEFCON={'NORMAL':{blocks:1,color:'#22c55e'},'ELEVATED':{blocks:2,color:'#ca8a04'},'HIGH':{blocks:3,color:'#ea580c'},'CRITICAL':{blocks:5,color:'#dc2626'}};
function updateDefcon(level,color){
  var def=DEFCON[level]||DEFCON['NORMAL'];
  var cnt=def.blocks,col=color||def.color,isCrit=(level==='CRITICAL');
  for(var i=0;i<5;i++){
    var b=document.getElementById('db'+i); if(!b) continue;
    if(i<cnt){b.className='defcon-block lit'+(isCrit?' blk-pulse':'');b.style.background=col;b.style.boxShadow='0 0 10px '+col+'80';}
    else{b.className='defcon-block';b.style.background='';b.style.boxShadow='';}
  }
  var lbl=document.getElementById('defconLabel');
  if(lbl){lbl.textContent='POSTURE: '+(level||'-');lbl.style.color=col;}
  var strip=document.getElementById('postureStrip');
  if(strip){strip.style.background=col;strip.style.boxShadow='0 0 16px '+col;}
}

/* KPI helpers */
function kpiLevel(id,val,warnT,dangerT){
  var el=document.getElementById(id);
  if(!el) return;
  el.classList.remove('ok','warn','danger');
  if(dangerT!=null&&val>=dangerT) el.classList.add('danger');
  else if(warnT!=null&&val>=warnT) el.classList.add('warn');
  else el.classList.add('ok');
}
function kpiDelta(id,cur,prev){
  var el=document.getElementById(id);
  if(!el) return;
  if(prev==null){ el.textContent=''; el.className='delta nc'; return; }
  var diff=cur-prev;
  if(diff===0||prev===0){ el.textContent='\u2014'; el.className='delta nc'; return; }
  var pct=Math.abs(Math.round((diff/Math.max(prev,1))*100));
  el.textContent=(diff>0?'\u2191':'\u2193')+pct+'%';
  el.className='delta '+(diff>0?'up':'down');
}

/* Render lists */
function renderIpList(el,pairs,tagMap){
  var q=document.getElementById('q').value;
  var pf=filterPairs(pairs,q);
  if(!pf.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=pf[0][1]||1;
  var total=pf.reduce(function(s,p){return s+(p[1]||0);},0)||1;
  var html='';
  pf.forEach(function(p,i){
    var tags=(tagMap&&tagMap[p[0]])||[];
    var barPct=Math.round(((p[1]||0)/maxV)*100);
    var pct=(((p[1]||0)/total)*100).toFixed(1)+'%';
    html+=listRow(i+1,p[0],p[1],barPct,pct,{ipClick:true,tags:tags});
  });
  el.innerHTML=html;
}
function renderList(el,data,flag,ipCol){
  var q=document.getElementById('q').value;
  var pairs=filterPairs(data,q);
  if(!pairs.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=pairs[0][1]||1;
  var total=pairs.reduce(function(s,p){return s+(p[1]||0);},0)||1;
  var html='';
  pairs.forEach(function(p,i){
    var barPct=Math.round(((p[1]||0)/maxV)*100);
    var pct=(((p[1]||0)/total)*100).toFixed(1)+'%';
    var isDanger=flag&&p[1]>100;
    html+=listRow(i+1,p[0],p[1],barPct,pct,{danger:isDanger,ipClick:ipCol,bgCls:isDanger?'danger':''});
  });
  el.innerHTML=html;
}
function renderStatus(el,obj){
  var q=document.getElementById('q').value;
  var keys=Object.keys(obj||{}).sort(function(a,b){ return obj[b]-obj[a]; });
  if(q&&q.trim()){ var t=q.toLowerCase(); keys=keys.filter(function(k){ return String(k).toLowerCase().includes(t); }); }
  keys=keys.slice(0,20);
  if(!keys.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No matches</span></div>';return;}
  var maxV=Math.max.apply(null,keys.map(function(k){return obj[k]||0;}).concat([1]));
  var total=keys.reduce(function(s,k){return s+(obj[k]||0);},0)||1;
  var html='';
  keys.forEach(function(k,i){
    var n=obj[k], code=parseInt(k,10);
    var is5xx=code>=500, is4xx=code>=400&&code<500, is3xx=code>=300&&code<400, is2xx=code>=200&&code<300;
    var valCls=is5xx?'danger':is4xx?'warn':is2xx?'ok':'';
    var bgCls=is5xx?'danger':'';
    var barPct=Math.round((n/maxV)*100);
    var pct=((n/total)*100).toFixed(1)+'%';
    html+=listRow(i+1,k+'',n,barPct,pct,{danger:is5xx,warn:is4xx,ok:is2xx,bgCls:bgCls});
  });
  el.innerHTML=html;
}

function renderAlerts(el,alerts){
  var q=document.getElementById('q').value;
  var arr=alerts||[];
  if(focusIp) arr=arr.filter(function(a){return a.ip===focusIp;});
  if(q&&q.trim()){var t=q.toLowerCase();arr=arr.filter(function(a){return String(a.ip+a.uri+(a.asn||'')+(a.country||'')+(a.tags||[]).join(' ')).toLowerCase().includes(t);});}
  if(!arr.length){el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">'+(focusIp?'No alerts for focus IP':'No alerts in buffer')+'</span></div>';return;}
  el.innerHTML=arr.map(function(a){
    var hl=(focusIp&&a.ip===focusIp)?' hl-focus':'';
    var sc=a.score||0,sevCls=sc>=10?' sev-hi':sc>=5?' sev-med':'',pillCls=scorePillCls(sc);
    var ap=(a.tags&&a.tags.length)?a.tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join(''):'';
    var flag=ccFlag(a.country||'');
    var key=a.ip+'|'+a.ts,isNew=!seenAlertKeys.has(key);
    seenAlertKeys.add(key);
    var ipGlow=sc>=10?'color:#f87171;text-shadow:0 0 10px rgba(248,113,113,0.6)':sc>=5?'color:#fb923c;text-shadow:0 0 8px rgba(251,146,60,0.5)':'color:var(--accent);text-shadow:0 0 8px rgba(0,212,255,0.4)';
    return '<div class="alert-row'+hl+sevCls+'" data-ip="'+escapeAttr(a.ip)+'">'
      +'<div class="alert-hd">'
        +'<span class="score-pill '+pillCls+'">+'+sc+'</span>'
        +'<span class="alert-ip" style="'+ipGlow+'" title="'+escapeAttr(a.ip)+'">'+escapeHtml(a.ip)+'</span>'
        +(flag?'<span class="alert-flag">'+flag+'</span>':'')
        +(a.country&&a.country!=='??'?'<span class="alert-cc">'+escapeHtml(a.country)+'</span>':'')
        +(ap?'<span class="alert-tags">'+ap+'</span>':'')
        +(isNew?'<span class="new-badge">NEW</span>':'')
        +'<span class="alert-time">'+timeAgo(a.ts)+'</span>'
      +'</div>'
      +'<div class="alert-uri" title="'+escapeAttr(a.uri)+'">'+escapeHtml(a.uri)+'</div>'
      +(a.asn||a.ua?'<div class="alert-meta">'+escapeHtml(a.asn||'')+(a.ua?'<span class="alert-sep">\u2022</span><span class="alert-ua">'+escapeHtml(a.ua)+'</span>':'')+'</div>':'')
      +'</div>';
  }).join('');
}

function renderThreats(el,rows){
  var q=document.getElementById('q').value;
  var r=rows||[];
  if(q&&q.trim()){var t=q.toLowerCase();r=r.filter(function(tw){return String(tw.ip+tw.asn+tw.top_path+(tw.country||'')+(tw.tags||[]).join(' ')).toLowerCase().includes(t);});}
  if(focusIp) r=r.filter(function(tw){return tw.ip===focusIp;});
  if(!r.length){el.innerHTML='<div class="th-row"><span></span><span class="ip" style="color:var(--muted)">'+(focusIp?'No threats for focus':'No scored sources')+'</span></div>';return;}
  // Use a global score floor so bars reflect absolute severity, not just relative rank.
  var absMax=Math.max.apply(null,r.map(function(t){return t.score||0;}).concat([50]));
  el.innerHTML=r.map(function(t,i){
    var hl=(focusIp&&t.ip===focusIp)?' hl-focus':'',rankCls=i===0?' rank1':'',rankNumCls=i===0?' r1':'';
    // Show at most 3 tags inline; extras go to the title tooltip
    var allTags=t.tags||[];
    var visibleTags=allTags.slice(0,3);
    var hiddenCount=allTags.length-visibleTags.length;
    var tp=visibleTags.map(function(x){return '<span class="tag tag-'+escapeAttr(x)+'">'+escapeHtml(x)+'</span>';}).join('');
    if(hiddenCount>0) tp+='<span class="tag" style="opacity:.55">+'+hiddenCount+'</span>';
    // Continuous bar: width proportional to score vs absMax, min 3%
    var pct=Math.max(3,Math.round((t.score/absMax)*100));
    var barColor=t.score>=20?'var(--danger)':t.score>=10?'#ea580c':'var(--warn)';
    var barGlow=t.score>=20?'var(--danger-glow)':t.score>=10?'rgba(234,88,12,0.5)':'rgba(245,158,11,0.4)';
    var flag=ccFlag(t.country||'');
    var tipText=(t.asn||'')+(t.top_path?' \u2014 '+t.top_path:'')+(allTags.length?' | '+allTags.join(', '):'');
    return '<div class="th-row'+hl+rankCls+'" data-ip="'+escapeAttr(t.ip)+'" title="'+escapeAttr(tipText)+'">'
      +'<span class="rank'+rankNumCls+'">'+(i+1)+'</span>'
      +'<span class="ip">'+escapeHtml(t.ip)+'</span>'
      +(tp?'<span class="th-tags">'+tp+'</span>':'<span class="th-tags"></span>')
      +'<div class="sc-bar-wrap"><div class="sc-bar-track"><div class="sc-bar" style="width:'+pct+'%;background:'+barColor+';box-shadow:0 0 6px '+barGlow+'"></div></div><span class="sc-num">'+t.score+'</span></div>'
      +'<span class="hits">'+t.hits+'</span>'
      +'<span class="cc" title="'+escapeHtml(t.country||'?')+'">'+(flag||escapeHtml(t.country||'?'))+'</span>'
      +'</div>';
  }).join('');
}


function statusBuckets(st){
  var a=[0,0,0,0,0];
  Object.keys(st||{}).forEach(function(k){
    var v=+st[k], c=parseInt(k,10);
    if(c>=200&&c<300) a[0]+=v;
    else if(c>=300&&c<400) a[1]+=v;
    else if(c>=400&&c<500) a[2]+=v;
    else if(c>=500&&c<600) a[3]+=v;
    else a[4]+=v;
  });
  return a;
}

function confCls(n){ return n>=70?'hi':n>=40?'med':'lo'; }

function renderBotnetCampaigns(el,campaigns){
  var arr=campaigns||[];
  bnCampaignMap={};
  arr.forEach(function(c){ bnCampaignMap[c.id]=c; });
  if(!arr.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No active campaigns detected &mdash; waiting for coordinated multi-IP probes</span></div>';
    return;
  }
  el.innerHTML=arr.map(function(c){
    var cls=confCls(c.confidence);
    var flags=(c.countries||[]).slice(0,7).map(function(cc){return ccFlag(cc)||cc;}).join('');
    var age=timeAgo(new Date(c.detected_at*1000).toISOString());
    return '<div class="bn-row" data-bn-id="'+escapeAttr(c.id)+'" title="Click to view campaign detail">'
      +'<span class="bn-id">'+escapeHtml(c.id)+'</span>'
      +'<span class="bn-uri" title="'+escapeAttr(c.trigger_uri)+'">'+escapeHtml(c.trigger_uri)+'</span>'
      +'<span class="bn-num">'+c.ip_count+'</span>'
      +'<span class="bn-num">'+c.asn_count+'</span>'
      +'<span class="bn-flags">'+flags+'</span>'
      +'<div class="bn-conf">'
        +'<div class="bn-conf-track"><div class="bn-conf-fill '+cls+'" style="width:'+c.confidence+'%"></div></div>'
        +'<span class="bn-conf-val '+cls+'">'+c.confidence+'</span>'
      +'</div>'
      +'</div>';
  }).join('');
}

function renderSources(el,sources,logPaths,ingestEnabled){
  if(!el) return;
  var rows=Object.entries(sources||{}).sort(function(a,b){return b[1]-a[1];});
  // show tailed paths that have no events yet too
  (logPaths||[]).forEach(function(p){
    if(!sources||sources[p]===undefined) rows.push([p,0]);
  });
  if(!rows.length&&!ingestEnabled){el.innerHTML='<div style="padding:10px 14px;color:var(--muted);font-size:12px">No sources configured</div>';return;}
  var h='';
  rows.forEach(function(r){
    var label=r[0],count=r[1];
    var isFile=label.startsWith('/');
    var icon=isFile? '&#128196;' : '&#127760;';
    var removeBtn=isFile?'':'<button type="button" class="src-remove-btn" data-src="'+escapeAttr(label)+'" style="margin-left:6px;background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;line-height:1;padding:0 2px" title="Remove source">&times;</button>';
    h+='<div style="display:flex;align-items:center;gap:8px;padding:7px 14px;border-bottom:1px solid var(--border)">'
      +'<span style="font-size:13px">'+icon+'</span>'
      +'<span style="flex:1;font-size:11px;word-break:break-all;color:var(--fg)">'+escapeHtml(label)+'</span>'
      +'<span style="font-size:12px;color:var(--muted);white-space:nowrap">'+count.toLocaleString()+' events</span>'
      +removeBtn
      +'</div>';
  });
  if(ingestEnabled){
    h+='<div style="padding:6px 14px;font-size:10px;color:var(--ok)">HTTP ingest endpoint active (POST /api/ingest)</div>';
  }
  el.innerHTML=h;
}

function renderBanList(d){
  var el=document.getElementById('banList');
  var bans=d.banned_ips||[];
  var mh=d.muted_hits||{};
  var notes=d.ban_notes||{};
  if(!bans.length){ el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No muted IPs</span></div>'; return; }
  el.innerHTML=bans.map(function(ip){
    var c=mh[ip]||0;
    var note=notes[ip]||'';
    var noteHtml='';
    if(note){
      var cls='ban-note';
      if(note==='audit') cls+=' ban-note-audit';
      else if(note==='http_abuse') cls+=' ban-note-http';
      else if(note.indexOf('auto:')===0) cls+=' ban-note-auto';
      noteHtml='<span class="'+cls+'" title="'+escapeAttr(note)+'">'+escapeHtml(note)+'</span>';
    }
    return '<div class="ban-row"><span class="kip" title="'+escapeAttr(ip)+'">'+escapeHtml(ip)+'</span>'
      +noteHtml
      +'<span class="cnt">'+c+' excl.</span>'
      +'<button type="button" class="toolbtn" data-unban="'+escapeAttr(ip)+'">Unmute</button></div>';
  }).join('');
}

/* Poll control */
function setPoll(ms){
  pollMs=ms;
  document.querySelectorAll('.poll-opt').forEach(function(b){ b.classList.toggle('on',+b.dataset.ms===ms); });
  schedulePoll();
}
function schedulePoll(){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer=null;
  if(paused||pollMs<=0) return;
  pollTimer=setInterval(load,pollMs);
}
function setPaused(p){
  paused=p;
  document.getElementById('btnPause').classList.toggle('on',p);
  document.getElementById('btnPause').innerText=p?'Resume':'Pause';
  document.getElementById('freezeBadge').style.display=p?'inline-flex':'none';
  schedulePoll();
}

function exportJson(){
  if(!lastPayload) return;
  var blob=new Blob([JSON.stringify(lastPayload,null,2)],{type:'application/json'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='sentinel-snapshot.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

/* IP Modal */
function closeModal(){ document.getElementById('modalBg').classList.remove('open'); }

/* Botnet campaign modal */
function closeBnModal(){ document.getElementById('bnModalBg').classList.remove('open'); }

function openBnModal(id){
  var c=bnCampaignMap[id];
  if(!c) return;
  var cls=confCls(c.confidence);
  var clsColor=cls==='hi'?'var(--danger)':cls==='med'?'var(--warn)':'var(--ok)';

  document.getElementById('bnModalId').textContent=c.id;
  document.getElementById('bnModalConfBadge').innerHTML=
    '<span class="bn-conf-badge" style="color:'+clsColor+'">'
    +'<span style="font-size:10px">&#9679;</span> '+c.confidence+'% confidence'
    +'</span>';
  document.getElementById('bnModalUri').textContent=c.trigger_uri;
  document.getElementById('bnMHits').textContent=(c.total_hits||0).toLocaleString();
  document.getElementById('bnMIpCount').textContent=c.ip_count||0;
  document.getElementById('bnMSubnets').textContent=c.subnet_count||0;
  document.getElementById('bnMAsns').textContent=c.asn_count||0;
  document.getElementById('bnMCountries').textContent=c.country_count||0;
  document.getElementById('bnMBurst').textContent=c.burst_peak_10s||0;
  document.getElementById('bnMDetected').textContent=timeAgo(new Date(c.detected_at*1000).toISOString());
  document.getElementById('bnMLastActive').textContent=timeAgo(new Date(c.last_active*1000).toISOString());

  var uaWrap=document.getElementById('bnMSharedUaWrap');
  if(c.shared_ua_ips>0){
    document.getElementById('bnMSharedUa').textContent=c.shared_ua_ips;
    uaWrap.style.display='';
  } else { uaWrap.style.display='none'; }

  var seqWrap=document.getElementById('bnMSharedSeqWrap');
  if(c.shared_seq_ips>0){
    document.getElementById('bnMSharedSeq').textContent=c.shared_seq_ips;
    seqWrap.style.display='';
  } else { seqWrap.style.display='none'; }

  // IP list
  var ips=c.ips||[];
  var ipTotal=c.ip_count||ips.length;
  document.getElementById('bnMIpHint').textContent=ips.length<ipTotal?'(showing '+ips.length+' of '+ipTotal+')':'';
  var geo=lastPayload&&lastPayload.geo||{};
  document.getElementById('bnModalIpList').innerHTML=ips.length
    ? ips.map(function(ip){
        var g=geo[ip]||{}, cc=g.country||'', flag=ccFlag(cc)||'';
        return '<div class="bn-modal-ip-row" data-ip="'+escapeAttr(ip)+'">'
          +(flag?'<span style="font-size:12px">'+flag+'</span>':'')
          +'<span class="ip">'+escapeHtml(ip)+'</span>'
          +(cc&&cc!=='??'?'<span style="font-size:10px;color:var(--muted)">'+escapeHtml(cc)+'</span>':'')
          +'</div>';
      }).join('')
    : '<div style="padding:10px 12px;color:var(--muted);font-size:11px">No IP detail available</div>';

  // ASN + country list
  var asns=c.asns||[];
  var countries=c.countries||[];
  var asnHtml=asns.map(function(a){
    return '<div class="bn-modal-asn-row"><span class="asn">'+escapeHtml(a)+'</span></div>';
  }).join('');
  var ccHtml=countries.map(function(cc){
    var flag=ccFlag(cc)||'';
    return '<div class="bn-modal-asn-row">'
      +(flag?'<span class="flag">'+flag+'</span>':'')
      +'<span class="asn">'+escapeHtml(cc)+'</span>'
      +'</div>';
  }).join('');
  document.getElementById('bnModalAsnList').innerHTML=
    (asnHtml?'<div style="padding:5px 12px;font-size:9px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase">ASNs</div>'+asnHtml:'')
    +(ccHtml?'<div style="padding:5px 12px;font-size:9px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;border-top:1px solid var(--border)">Countries</div>'+ccHtml:'')
    ||'<div style="padding:10px 12px;color:var(--muted);font-size:11px">No data</div>';

  document.getElementById('bnModalBg').classList.add('open');
}



async function openIpModal(ip){
  if(!ip) return;
  modalIp=ip;
  var mbn=document.getElementById('modalBanNote');
  if(mbn) mbn.value='';
  document.getElementById('modalIpText').innerText=ip;
  document.getElementById('modalFlag').innerText='';
  document.getElementById('modalCcPill').style.display='none';
  document.getElementById('modalGeoStrip').style.display='none';
  document.getElementById('modalTagsRow').style.display='none';
  document.getElementById('mStatHits').innerText='\u2014';
  document.getElementById('mStatScore').innerText='\u2014';
  document.getElementById('mStatPaths').innerText='\u2014';
  document.getElementById('mStatClass').innerText='...';
  document.getElementById('mStatClass').className='modal-stat-val';
  document.getElementById('mStatEnrichWrap').style.display='none';
  document.getElementById('mStatEnrich').innerText='\u2014';
  document.getElementById('mStatIpinfoWrap').style.display='none';
  document.getElementById('mStatIpinfo').innerText='\u2014';
  document.getElementById('mStatAbuseWrap').style.display='none';
  document.getElementById('mStatAbuse').innerText='\u2014';
  document.getElementById('mStatGnWrap').style.display='none';
  document.getElementById('mStatGn').innerText='\u2014';
  document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--muted);font-family:var(--mono);font-size:12px;text-align:center">Loading\u2026</div>';
  var _uaW=document.getElementById('modalUaWrap'); if(_uaW) _uaW.style.display='none';
  document.getElementById('modalBg').classList.add('open');
  try{
    var res=await fetch('/api/ip?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    var j=await res.json();
    if(!res.ok){
      document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">'+escapeHtml(j.error||'Error')+'</div>';
    } else {
    var g=j.geo||{}, cc=g.country||'', flag=ccFlag(cc);
    var asnRaw=g.asn||'', asnParts=asnRaw.split(' | ');
    var asnNum=asnParts[0]||'', isp=asnParts[1]||asnParts[0]||'';
    var sc=j.score||0, tags=j.tags||[], paths=j.paths||[];

    if(flag) document.getElementById('modalFlag').innerText=flag;
    if(cc&&cc!=='??'){
      var pill=document.getElementById('modalCcPill');
      pill.innerText=cc; pill.style.display='inline-flex';
    }

    // Stat strip
    var scoreEl=document.getElementById('mStatScore');
    scoreEl.innerText=sc;
    scoreEl.className='modal-stat-val '+(sc>=10?'hi':sc>=5?'med':'ok');
    document.getElementById('mStatHits').innerText=(j.hits||0).toLocaleString();
    document.getElementById('mStatPaths').innerText=paths.length;
    var classEl=document.getElementById('mStatClass');
    if(tags.length){
      classEl.innerHTML=tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join(' ');
      classEl.className='modal-stat-val';
    } else {
      classEl.innerText='clean'; classEl.className='modal-stat-val ok';
    }

    // Geo strip
    var geoItems=[];
    if(isp) geoItems.push(['ISP / Org',isp]);
    if(asnNum&&asnNum!==isp) geoItems.push(['ASN',asnNum]);
    if(cc&&cc!=='??') geoItems.push(['Country',cc]);
    if(geoItems.length){
      var gs=document.getElementById('modalGeoStrip');
      gs.innerHTML=geoItems.map(function(item){
        return '<div class="modal-geo-item"><div class="geo-lbl">'+escapeHtml(item[0])+'</div><div class="geo-val" title="'+escapeAttr(item[1])+'">'+escapeHtml(item[1])+'</div></div>';
      }).join('');
      gs.style.display='flex';
    }

    // Tags row
    if(tags.length){
      var tr=document.getElementById('modalTagsRow');
      tr.innerHTML='<span class="modal-tags-lbl">Tags</span>'
        +tags.map(function(t){return '<span class="tag tag-'+escapeAttr(t)+'">'+escapeHtml(t)+'</span>';}).join('');
      tr.style.display='flex';
    }

    // UA list
    var uas=j.uas||[];
    var uaWrap=document.getElementById('modalUaWrap');
    var uaList=document.getElementById('modalUaList');
    if(uaWrap&&uaList){
      if(uas.length){
        uaWrap.style.display='';
        uaList.innerHTML=uas.map(function(ua){
          return '<div class="path-row" style="grid-template-columns:1fr;padding:4px 10px">'
            +'<span class="path-row-text" title="'+escapeAttr(ua)+'" style="color:var(--text);font-size:11px;font-family:var(--mono)">'+escapeHtml(ua)+'</span>'
            +'</div>';
        }).join('');
      } else {
        uaWrap.style.display='none';
      }
    }

    // Paths list
    if(!paths.length){
      document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--muted);font-family:var(--mono);font-size:12px;text-align:center">No path data recorded</div>';
    } else {
      var total=paths.reduce(function(s,p){return s+(p[1]||0);},0)||1;
      var maxH=paths[0][1]||1;
      document.getElementById('modalPaths').innerHTML=paths.map(function(p,i){
        var barPct=Math.round(((p[1]||0)/maxH)*100);
        var sharePct=(((p[1]||0)/total)*100).toFixed(1);
        return '<div class="path-row">'
          +'<div class="path-row-bg" style="width:'+barPct+'%"></div>'
          +'<span class="path-row-rank'+(i===0?' r1':'')+'">'+(i+1)+'</span>'
          +'<span class="path-row-text" title="'+escapeAttr(p[0])+'">'+escapeHtml(p[0])+'</span>'
          +'<span class="path-row-hits">'+p[1]+'</span>'
          +'<span class="path-row-pct">'+sharePct+'%</span>'
          +'</div>';
      }).join('');
    }
    } // end else (res.ok)
  }catch(e){
    document.getElementById('modalPaths').innerHTML='<div style="padding:28px 12px;color:var(--danger);font-family:var(--mono);font-size:12px;text-align:center">Request failed</div>';
  }
  // Shodan InternetDB + IPInfo -- fire-and-forget, does not block modal open
  try{
    var er=await fetch('/api/ipenrich?ip='+encodeURIComponent(ip),{credentials:'same-origin'});
    if(er.ok){
      var ej=await er.json();
      if(ej.ok){
        // Shodan
        var sd=ej.shodan||{};
        var sWrap=document.getElementById('mStatEnrichWrap');
        var sEl=document.getElementById('mStatEnrich');
        if(sWrap&&sEl){
          var sParts=[];
          if(sd.ports&&sd.ports.length) sParts.push(sd.ports.length+' port'+(sd.ports.length===1?'':'s')+': '+sd.ports.slice(0,8).join(', ')+(sd.ports.length>8?'...':''));
          if(sd.vulns&&sd.vulns.length) sParts.push(sd.vulns.length+' CVE'+(sd.vulns.length===1?'':'s')+': '+sd.vulns.slice(0,3).join(', ')+(sd.vulns.length>3?'...':''));
          if(sd.tags&&sd.tags.length) sParts.push('tags: '+sd.tags.join(', '));
          if(sd.hostnames&&sd.hostnames.length) sParts.push(sd.hostnames.slice(0,3).join(', ')+(sd.hostnames.length>3?'...':''));
          if(Object.keys(sd).length){
            sWrap.style.display='';
            sEl.innerText=sParts.length?sParts.join(' | '):'not indexed';
            sEl.className='modal-stat-val '+(sd.vulns&&sd.vulns.length?'hi':'');
          }
        }
        // IPInfo
        var ii=ej.ipinfo||{};
        var iWrap=document.getElementById('mStatIpinfoWrap');
        var iEl=document.getElementById('mStatIpinfo');
        if(iWrap&&iEl){
          var iParts=[];
          if(ii.org) iParts.push(ii.org);
          if(ii.city||ii.region||ii.country) iParts.push([ii.city,ii.region,ii.country].filter(Boolean).join(', '));
          if(ii.timezone) iParts.push(ii.timezone);
          if(ii.abuse_contact) iParts.push('abuse: '+ii.abuse_contact);
          if(iParts.length){
            iWrap.style.display='';
            iEl.innerText=iParts.join(' | ');
            iEl.className='modal-stat-val';
          }
          // Backfill geo strip if /api/ip didn't have resolved geo yet
          var gs=document.getElementById('modalGeoStrip');
          if(gs&&gs.style.display==='none'&&(ii.org||ii.country)){
            var geoItems=[];
            if(ii.org) geoItems.push(['ISP / Org',ii.org]);
            if(ii.country&&ii.country!=='??') geoItems.push(['Country',ii.country]);
            if(ii.city) geoItems.push(['City',ii.city]);
            if(geoItems.length){
              gs.innerHTML=geoItems.map(function(item){
                return '<div class="modal-geo-item"><div class="geo-lbl">'+escapeHtml(item[0])+'</div><div class="geo-val" title="'+escapeAttr(item[1])+'">'+escapeHtml(item[1])+'</div></div>';
              }).join('');
              gs.style.display='flex';
            }
          }
        }
        // AbuseIPDB
        var ab=ej.abuseipdb||{};
        var aWrap=document.getElementById('mStatAbuseWrap');
        var aEl=document.getElementById('mStatAbuse');
        if(aWrap&&aEl&&(ab.abuse_score!=null||ab.total_reports!=null)){
          var abParts=[];
          if(ab.abuse_score!=null) abParts.push('score: '+ab.abuse_score+'%');
          if(ab.total_reports) abParts.push(ab.total_reports+' report'+(ab.total_reports===1?'':'s'));
          if(ab.usage_type) abParts.push(ab.usage_type);
          if(ab.is_whitelisted) abParts.push('whitelisted');
          if(abParts.length){
            aWrap.style.display='';
            aEl.innerText=abParts.join(' | ');
            var sc=ab.abuse_score||0;
            aEl.className='modal-stat-val '+(sc>=75?'hi':sc>=25?'med':'ok');
          }
        }
        // GreyNoise
        var gn=ej.greynoise||{};
        var gnWrap=document.getElementById('mStatGnWrap');
        var gnEl=document.getElementById('mStatGn');
        if(gnWrap&&gnEl&&(gn.classification||gn.noise!=null)){
          var gnParts=[];
          if(gn.classification&&gn.classification!=='unknown') gnParts.push(gn.classification);
          if(gn.noise) gnParts.push('noise');
          if(gn.riot) gnParts.push('riot');
          if(gn.name) gnParts.push(gn.name);
          if(gnParts.length){
            gnWrap.style.display='';
            gnEl.innerText=gnParts.join(' | ');
            gnEl.className='modal-stat-val '+(gn.classification==='malicious'?'hi':gn.riot?'ok':'med');
          }
        }
      }
    }
  }catch(_e){}
}

function _updateFocusBar(){
  var parts=[];
  if(focusIp) parts.push('IP: '+focusIp);
  if(focusHost) parts.push('host: '+focusHost);
  if(focusRef) parts.push('ref: '+focusRef);
  document.getElementById('focusLbl').innerText=parts.length?('['+parts.join(' | ')+']'):'';
  document.getElementById('btnClearFocus').style.display=parts.length?'inline-block':'none';
  var hl=document.getElementById('hostFocusLbl');
  if(hl) hl.innerText=focusHost?('['+focusHost+']'):'';
  var rl=document.getElementById('refFocusLbl');
  if(rl) rl.innerText=focusRef?('['+focusRef+']'):'';
}

function setFocus(ip){
  focusIp=ip||'';
  _updateFocusBar();
  if(lastPayload) applyRender(lastPayload);
  historyPage=1;
  loadHistoryEvents();
}

function setFocusHost(host){
  focusHost=host||'';
  _updateFocusBar();
  if(lastPayload) applyRender(lastPayload);
  historyPage=1;
  loadHistoryEvents();
}

function setFocusRef(ref){
  focusRef=ref||'';
  _updateFocusBar();
  historyPage=1;
  loadHistoryEvents();
}

function toggleIpFocus(ip){
  if(!ip) return;
  if(focusIp===ip){
    setFocus('');
    closeModal();
    return;
  }
  setFocus(ip);
  openIpModal(ip);
}

function fmtFp(fp){
  // Shorten long fingerprint strings for display
  if(!fp) return '(none)';
  if(fp.length<=32) return fp;
  return fp.slice(0,12)+'...'+fp.slice(-8);
}

function renderTlsFp(el,rows){
  if(!el) return;
  if(!rows||!rows.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No shared fingerprints detected</span></div>';
    return;
  }
  var h='';
  rows.forEach(function(r){
    var fp=r[0]||'', cnt=r[1]||0;
    var isCf=!/^tls:/.test(fp);
    var label=isCf?'JA3':'TLS';
    var tagCls=isCf?'tag-bot':'tag-scan';
    h+='<div class="list-row" style="gap:6px">';
    h+='<span class="list-key" style="font-family:var(--mono);font-size:10px;flex:1;min-width:0" title="'+escapeAttr(fp)+'"><span class="tag '+tagCls+'">'+label+'</span> '+escapeHtml(fmtFp(fp))+'</span>';
    h+='<span class="list-val" style="color:var(--accent3);flex-shrink:0">'+cnt+' IPs</span>';
    h+='<button class="toolbtn danger tls-fp-del-btn" data-fp="'+escapeAttr(fp)+'" style="font-size:9px;padding:2px 8px;flex-shrink:0" title="Delete this fingerprint cluster">&#10005;</button>';
    h+='</div>';
  });
  el.innerHTML=h;
}

function fmtStorageBytes(b){
  if(b==null) return '0 B';
  if(b<1024) return b+' B';
  if(b<1048576) return (b/1024).toFixed(1)+' KB';
  if(b<1073741824) return (b/1048576).toFixed(2)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}

function renderStorage(el,s){
  if(!el||!s) return;
  var labels={
    bans:'Ban list',
    audit:'Audit log',
    parsed_state:'Parsed state',
    behavior_state:'Behavior state',
    history_buckets:'History buckets',
    history_events:'History events'
  };
  var order=['bans','audit','parsed_state','behavior_state','history_buckets','history_events'];
  var h='';
  order.forEach(function(k){
    var sz=s[k]||0;
    var extra='';
    if(k==='history_events'&&s.history_events_files) extra=' <span style="color:var(--muted)">'+s.history_events_files+' files</span>';
    h+='<div class="list-row">';
    h+='<span class="list-key">'+labels[k]+'</span>';
    h+='<span class="list-val" style="color:var(--accent)">'+fmtStorageBytes(sz)+extra+'</span>';
    h+='</div>';
  });
  h+='<div class="list-row" style="border-top:1px solid var(--border);margin-top:4px">';
  h+='<span class="list-key" style="font-weight:600">Total</span>';
  h+='<span class="list-val" style="color:var(--ok);font-weight:600">'+fmtStorageBytes(s.total||0)+'</span>';
  h+='</div>';
  el.innerHTML=h;
}

function applyRender(d){
  renderIpList(document.getElementById('ips'),d.ips,d.ip_tags||{});
  renderList(document.getElementById('domains'),d.domains);
  renderList(document.getElementById('paths'),d.paths);
  renderList(document.getElementById('refs'),d.referers);
  renderList(document.getElementById('asn'),d.asn);
  renderStatus(document.getElementById('status'),d.status);
  renderAlerts(document.getElementById('alerts'),d.alerts);
  renderThreats(document.getElementById('threats'),d.top_threats);
  renderBotnetCampaigns(document.getElementById('botnets'),d.botnet_campaigns);
  renderSources(document.getElementById('sourcesList'),d.sources,d.log_paths,d.ingest_enabled);
  renderTlsFp(document.getElementById('tlsFpList'),d.tls_fp_shared||[]);
  renderStorage(document.getElementById('storageList'),d.storage||{});
  updateWorldMap(d.countries);
}

/* Main load */
async function load(force){
  if(paused&&!force) return;
  var d;
  try{
    var res=await fetch('/data',{credentials:'same-origin'});
    if(res.status===401){
      document.getElementById('foot').innerText='401: reload and sign in (Basic auth for this origin)';
      return;
    }
    d=await res.json();
  }catch(e){ return; }
  lastPayload=d;
  currentBannedSet=new Set(d.banned_ips||[]);
  lastLoadMs=Date.now();

  var ab=document.getElementById('authBadge');
  if(ab) ab.style.display=d.auth_enabled?'inline-flex':'none';

  /* DEFCON posture */
  updateDefcon(d.threat_level||'NORMAL', d.threat_color);

  /* KPI values */
  var rpsV=d.rps||0, peakV=d.peak||0, totalV=d.total||0, uniqV=d.unique_ips||0;
  var errpctV=parseFloat(d.error_rate_pct||0), atkV=d.attack_rps_last_tick||0;
  var clientE=d.client_errors||0, serverE=d.server_errors||0;

  document.getElementById('rps').innerText=rpsV;
  document.getElementById('peak').innerText=peakV;
  document.getElementById('total').innerText=totalV.toLocaleString();
  document.getElementById('uniq').innerText=uniqV;
  document.getElementById('errs').innerText=clientE+' / '+serverE;
  document.getElementById('errpct').innerText=errpctV+'%';
  document.getElementById('atk').innerText=atkV;
  document.getElementById('mutedTotal').innerText=d.muted_total||0;
  document.getElementById('bytesServed').innerText=fmtBytes(d.bytes_served||0);

  /* KPI color thresholds */
  kpiLevel('kpi-rps',    rpsV,    20, 80);
  kpiLevel('kpi-peak',   peakV,   20, 80);
  kpiLevel('kpi-uniq',   uniqV,   50, 200);
  kpiLevel('kpi-errs',   clientE+serverE, 10, 50);
  kpiLevel('kpi-errpct', errpctV, 5,  20);
  kpiLevel('kpi-atk',    atkV,    2,  10);

  /* KPI deltas */
  kpiDelta('delta-rps',    rpsV,    prevKpi.rps);
  kpiDelta('delta-peak',   peakV,   prevKpi.peak);
  kpiDelta('delta-uniq',   uniqV,   prevKpi.uniq);
  kpiDelta('delta-errpct', errpctV, prevKpi.errpct);
  kpiDelta('delta-atk',    atkV,    prevKpi.atk);
  prevKpi={rps:rpsV,peak:peakV,uniq:uniqV,errpct:errpctV,atk:atkV};

  /* Charts */
  if(!historyMode){
    rpsHist.push(rpsV);
    var lastAtk=(d.attack_timeline&&d.attack_timeline.length)?d.attack_timeline[d.attack_timeline.length-1]:0;
    atkHist.push(lastAtk);
    if(rpsHist.length>MAX) rpsHist.shift();
    if(atkHist.length>MAX) atkHist.shift();
    var labels=rpsHist.map(function(_,i){ return i; });
    comboChart.data.labels=labels;
    comboChart.data.datasets[0].data=rpsHist.slice();
    comboChart.data.datasets[1].data=atkHist.slice();
    comboChart.update('none');
  }else{
    applyHistoryChart(historyPoints);
  }
  statusDonut.data.datasets[0].data=statusBuckets(d.status);
  statusDonut.update('none');

  var renderErr=null;
  try{
    applyRender(d);
    renderBanList(d);
    renderWhitelist(d);
    renderIpWhitelist(d.whitelisted_ips||[]);
  }catch(e){
    renderErr=e;
    console.error('render failure',e);
  }

  /* Alert count / tab title */
  var alertCount=(d.alerts||[]).length;
  if(!isPageVisible&&alertCount>knownAlertCount){
    newAlertsSinceBlur+=alertCount-knownAlertCount;
    document.title='('+newAlertsSinceBlur+') Sentinel | SOC';
  }
  knownAlertCount=alertCount;

  var ih=document.getElementById('iptablesHintP');
  if(ih){ih.textContent=d.iptables_enabled?('iptables DROP on chain '+d.iptables_chain+' enabled.'):('iptables off \u2014 set SENTINEL_IPTABLES=1 to sync rules.');}
  var ihs=document.getElementById('iptablesHintShort');
  if(ihs) ihs.textContent=d.iptables_enabled?'mute + iptables':'mute list';

  var up=d.stream_uptime_s!=null?(' | stream '+d.stream_uptime_s+'s'):'';
  var poll=paused?'paused':(pollMs/1000)+'s';
  var au=d.audit_log?' | audit on':'';
  document.getElementById('foot').innerText='Server '+d.server_time+up+' | poll '+poll+au+(renderErr?' | render error':'');
  initWorldMap();
  refreshHistory();
}

/* Sidebar toggle */
document.getElementById('sbToggle').addEventListener('click',function(){
  sidebarOpen=!sidebarOpen;
  document.getElementById('layout').classList.toggle('sb-hidden',!sidebarOpen);
  document.getElementById('sbToggle').innerHTML=sidebarOpen?'&#9664;':'&#9654;';
});

/* Event wiring */
document.getElementById('btnPause').addEventListener('click',function(){ setPaused(!paused); });
document.querySelectorAll('.poll-opt').forEach(function(b){
  b.addEventListener('click',function(){ setPaused(false); setPoll(+b.dataset.ms); });
});
document.querySelectorAll('.hist-range').forEach(function(b){
  b.addEventListener('click',function(){
    document.querySelectorAll('.hist-range').forEach(function(x){x.classList.remove('on');});
    b.classList.add('on');
    historySelectedDay='';
    var hsel=document.getElementById('histDaySelect');
    if(hsel) hsel.value='';
    historyRangeSec=+b.dataset.sec||2592000;
    historyPage=1;
    refreshHistory();
  });
});
document.getElementById('histDaySelect').addEventListener('change',function(e){
  historySelectedDay=(e.target.value||'').trim();
  historyPage=1;
  refreshHistory();
});
document.getElementById('btnHistMode').addEventListener('click',function(){
  historyMode=!historyMode;
  document.getElementById('btnHistMode').classList.toggle('on',historyMode);
  if(historyMode) applyHistoryChart(historyPoints);
});
document.getElementById('btnHistPrev').addEventListener('click',function(){
  if(historyPage<=1) return;
  historyPage-=1;
  loadHistoryEvents();
});
document.getElementById('btnHistNext').addEventListener('click',function(){
  var nextStart=historyPage*50;
  if(nextStart>=historyTotal) return;
  historyPage+=1;
  loadHistoryEvents();
});
document.getElementById('btnExport').addEventListener('click',exportJson);
document.getElementById('btnClearFocus').addEventListener('click',function(){
  focusIp=''; focusHost=''; focusRef='';
  _updateFocusBar();
  if(lastPayload) applyRender(lastPayload);
  historyPage=1; loadHistoryEvents();
});

function warnIptables(j){
  if(j&&j.iptables&&j.iptables.enabled&&!j.iptables.ok){ alert('iptables: '+(j.iptables.error||'failed')); }
}
async function removeSource(label){
  if(!confirm('Remove source "'+label+'" from the list?')) return;
  try{
    var r=await fetch('/api/source/remove',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:label})});
    if(!r.ok){ alert('Remove failed'); return; }
    await load(true);
  }catch(e){ alert('Remove failed'); }
}
document.getElementById('sourcesList').addEventListener('click',async function(e){
  var btn=e.target.closest('.src-remove-btn');
  if(!btn||!btn.dataset.src) return;
  e.stopPropagation();
  await removeSource(btn.dataset.src);
});
document.getElementById('btnBan').addEventListener('click',async function(){
  var ip=document.getElementById('banIp').value.trim();
  if(!ip) return;
  var noteEl=document.getElementById('banNote');
  var note=noteEl?noteEl.value.trim():'';
  try{
    var body={ip:ip};
    if(note) body.note=note;
    var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    document.getElementById('banIp').value='';
    if(noteEl) noteEl.value='';
    await load(true);
  }catch(e){ alert('Mute failed'); }
});
document.getElementById('banList').addEventListener('click',async function(e){
  var b=e.target.closest('[data-unban]');
  if(!b||!b.dataset.unban) return;
  var ip=b.dataset.unban;
  try{
    var r=await fetch('/api/unban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Unmute failed'); return; }
    warnIptables(j);
    await load(true);
  }catch(err){ alert('Unmute failed'); }
});
/* Path whitelist */
function renderWhitelist(d){
  var el=document.getElementById('whitelistEntries');
  if(!el) return;
  var entries=d.whitelisted_paths||[];
  if(!entries.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No whitelisted paths</span></div>';
    return;
  }
  el.innerHTML=entries.map(function(p){
    return '<div class="ban-row">'
      +'<span class="kip" title="'+escapeAttr(p)+'">'+escapeHtml(p)+'</span>'
      +'<button type="button" class="toolbtn danger" data-wl-remove="'+escapeAttr(p)+'">Remove</button>'
      +'</div>';
  }).join('');
}
document.getElementById('btnWhitelistAdd').addEventListener('click',async function(){
  var p=document.getElementById('whitelistPath').value.trim();
  if(!p) return;
  try{
    var r=await fetch('/api/whitelist/add',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:p})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Add failed'); return; }
    document.getElementById('whitelistPath').value='';
    await load(true);
  }catch(e){ alert('Add failed'); }
});
document.getElementById('whitelistEntries').addEventListener('click',async function(e){
  var b=e.target.closest('[data-wl-remove]');
  if(!b||!b.dataset.wlRemove) return;
  var p=b.dataset.wlRemove;
  try{
    var r=await fetch('/api/whitelist/remove',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:p})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Remove failed'); return; }
    await load(true);
  }catch(err){ alert('Remove failed'); }
});

document.getElementById('btnIpWhitelistAdd').addEventListener('click',async function(){
  var ip=document.getElementById('whitelistIp').value.trim();
  if(!ip) return;
  try{
    var r=await fetch('/api/ip-whitelist/add',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Add failed'); return; }
    document.getElementById('whitelistIp').value='';
    renderIpWhitelist(j.whitelisted_ips||[]);
  }catch(e){ alert('Add failed'); }
});
document.getElementById('ipWhitelistEntries').addEventListener('click',async function(e){
  var b=e.target.closest('[data-ipwl-remove]');
  if(!b||!b.dataset.ipwlRemove) return;
  var ip=b.dataset.ipwlRemove;
  try{
    var r=await fetch('/api/ip-whitelist/remove',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Remove failed'); return; }
    renderIpWhitelist(j.whitelisted_ips||[]);
  }catch(err){ alert('Remove failed'); }
});
function renderIpWhitelist(ips){
  var el=document.getElementById('ipWhitelistEntries');
  if(!el) return;
  if(!ips||!ips.length){ el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No whitelisted IPs</span></div>'; return; }
  el.innerHTML=ips.map(function(ip){
    return '<div class="ban-row">'
      +'<span class="kip" title="'+escapeAttr(ip)+'">'+escapeHtml(ip)+'</span>'
      +'<button type="button" class="toolbtn danger" data-ipwl-remove="'+escapeAttr(ip)+'">Remove</button>'
      +'</div>';
  }).join('');
}

document.getElementById('btnReset').addEventListener('click',async function(){
  if(!confirm('Reset all counters, charts, alerts, audit log, and historical telemetry?')) return;
  try{
    var r=await fetch('/api/reset',{method:'POST',credentials:'same-origin'});
    // Only hard-abort if the server explicitly rejected the request.
    // A network-level failure (connection drop, timeout) still means the
    // server likely completed the reset — fall through to UI cleanup.
    if(r&&!r.ok){ alert('Reset failed (server returned '+r.status+')'); return; }
  }catch(e){ /* network error — reset probably ran, continue with UI cleanup */ }
  // Clean up UI regardless — the server-side state has been wiped.
  try{
    lastPayload=null; setFocus(''); closeModal(); seenAlertKeys.clear();
    rpsHist=[]; atkHist=[];
    comboChart.data.labels=[]; comboChart.data.datasets[0].data=[]; comboChart.data.datasets[1].data=[];
    comboChart.update('none');
    statusDonut.data.datasets[0].data=[0,0,0,0,0]; statusDonut.update('none');
    if(worldMap){try{worldMap.series.regions[0].setValues({});}catch(e){}}
    historySelectedDay=''; historyDaysLoaded=false; historyPage=1;
    var hsel=document.getElementById('histDaySelect');
    if(hsel) hsel.value='';
    auditLastCount=0;
    setPaused(false);
    await load(true);
    await refreshHistory();
    await loadAudit(true);
  }catch(e){}
});

document.getElementById('q').addEventListener('input',function(){ if(lastPayload) applyRender(lastPayload); });
document.getElementById('modalBg').addEventListener('click',function(e){ if(e.target.id==='modalBg') closeModal(); });
document.getElementById('modalClose').addEventListener('click',closeModal);
document.getElementById('modalCopy').addEventListener('click',function(){
  if(!modalIp) return;
  var btn=document.getElementById('modalCopy');
  function _flash(ok){
    var orig=btn.innerText;
    btn.innerText=ok?'Copied!':'Copy failed';
    btn.style.color=ok?'var(--ok)':'var(--danger)';
    setTimeout(function(){btn.innerText=orig;btn.style.color='';},1500);
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(modalIp).then(function(){_flash(true);},function(){_flash(false);});
  } else {
    // Fallback for HTTP (no clipboard API)
    var ta=document.createElement('textarea');
    ta.value=modalIp;ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.focus();ta.select();
    try{_flash(document.execCommand('copy'));}catch(e){_flash(false);}
    document.body.removeChild(ta);
  }
});
document.getElementById('modalExtLink').addEventListener('click',function(e){
  e.preventDefault();
  if(!modalIp) return;
  window.open('https://ipinfo.io/'+encodeURIComponent(modalIp),'_blank','noopener');
});
document.getElementById('modalBan').addEventListener('click',async function(){
  if(!modalIp) return;
  var noteEl=document.getElementById('modalBanNote');
  var note=noteEl?noteEl.value.trim():'';
  try{
    var body={ip:modalIp};
    if(note) body.note=note;
    var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Mute failed'); return; }
    warnIptables(j);
    if(noteEl) noteEl.value='';
    closeModal();
    await load(true);
  }catch(e){ alert('Mute failed'); }
});

document.getElementById('modalIpWhitelist').addEventListener('click',async function(){
  if(!modalIp) return;
  if(!confirm('Whitelist '+modalIp+'?\nAll traffic from this IP will be silently ignored — it will never appear in the panel.')) return;
  try{
    var r=await fetch('/api/ip-whitelist/add',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:modalIp})});
    var j=await r.json().catch(function(){ return {}; });
    if(!r.ok){ alert(j.error||'Whitelist failed'); return; }
    closeModal();
    await load(true);
  }catch(e){ alert('Whitelist failed'); }
});

document.body.addEventListener('click',function(e){
  var ipRow=e.target.closest('.row-ip');
  if(ipRow&&ipRow.dataset.ip){ toggleIpFocus(ipRow.dataset.ip); return; }
  var th=e.target.closest('.th-row[data-ip]');
  if(th&&th.dataset.ip){ toggleIpFocus(th.dataset.ip); return; }
  var ar=e.target.closest('.alert-row');
  if(ar&&ar.dataset.ip){ toggleIpFocus(ar.dataset.ip); return; }
  var hi=e.target.closest('.hist-ip-link');
  if(hi&&hi.dataset.ip){ toggleIpFocus(hi.dataset.ip); return; }
  // Host drill-down (from history table)
  var hhl=e.target.closest('.hist-host-link');
  if(hhl&&hhl.dataset.host){
    var hh=hhl.dataset.host;
    if(focusHost===hh){ setFocusHost(''); } else { setFocusHost(hh); }
    return;
  }
});

document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){ closeBnModal(); closeModal(); return; }
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); document.getElementById('q').focus(); }
});

/* Audit log */
var auditPollTimer=null;
var auditLastCount=0;

function renderAudit(entries){
  var el=document.getElementById('auditList');
  if(!el) return;
  if(!entries||!entries.length){
    el.innerHTML='<div class="list-row"><span class="list-key" style="color:var(--muted)">No audit entries yet</span></div>';
    return;
  }
  var ACTION_COLOR={'mute':'var(--danger)','unban':'var(--ok)','reset':'var(--warn)','auth_failed':'#f59e0b','audit_cleared':'#a78bfa','auto_ban':'#ef4444'};
  var html='';
  var shown=entries.slice(-50).reverse();
  for(var i=0;i<shown.length;i++){
    var e=shown[i];
    var ts=e.ts?(e.ts.replace('T',' ').replace(/\.[0-9]+([+-][0-9][0-9]:[0-9][0-9]|Z)?$/,'').replace('+00:00','')+' UTC'):'';
    var col=ACTION_COLOR[e.action]||'var(--accent)';
    var targetIp=(e.detail&&e.detail.ip)||(e.action==='auth_failed'?(e.remote||''):'');
    var isBanned=targetIp&&currentBannedSet.has(targetIp);
    var banBtn=targetIp
      ? '<span class="audit-ban-wrap" style="display:inline-flex;gap:4px;align-items:center;flex-shrink:0;margin-left:4px">'
        +(isBanned
          ? '<button type="button" class="toolbtn audit-unban-btn" data-ip="'+escapeAttr(targetIp)+'" style="font-size:9px;padding:2px 7px">Unmute</button>'
          : '<button type="button" class="toolbtn danger audit-ban-btn" data-ip="'+escapeAttr(targetIp)+'" style="font-size:9px;padding:2px 7px">Mute</button>'
        )
        +'</span>'
      : '';
    html+='<div class="list-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:5px 10px">'
      +'<div style="display:flex;gap:6px;width:100%;align-items:center">'
      +'<span style="color:'+col+';font-weight:700;text-transform:uppercase;font-size:10px;flex-shrink:0">'+escapeHtml(e.action||'')+'</span>'
      +'<span style="color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(e.user||'')+'</span>'
      +'<span style="color:var(--muted);font-size:10px;flex-shrink:0">'+escapeHtml(e.remote||'')+'</span>'
      +banBtn
      +'</div>'
      +'<div style="color:var(--muted);font-size:10px;display:flex;gap:6px;flex-wrap:wrap">'
      +'<span>'+escapeHtml(ts)+'</span>'
      +(targetIp?'<span style="color:var(--accent)">\u2192 <span class="hist-ip-link" data-ip="'+escapeAttr(targetIp)+'" style="cursor:pointer;text-decoration:underline;text-decoration-style:dotted" title="Click to drill down">'+escapeHtml(targetIp)+'</span></span>':'')
      +'</div>'
      +'</div>';
  }
  el.innerHTML=html;
}

async function loadAudit(force){
  var card=document.getElementById('auditCard');
  if(!card) return;
  try{
    var r=await fetch('/api/audit?limit=50',{credentials:'same-origin'});
    if(!r.ok) return;
    var j=await r.json();
    if(!j.audit_enabled){ card.style.display='none'; return; }
    card.style.display='';
    if(force||j.entries.length!==auditLastCount){
      auditLastCount=j.entries.length;
      renderAudit(j.entries);
    }
  }catch(e){}
}

function startAuditPoll(){
  loadAudit();
  auditPollTimer=setInterval(loadAudit,5000);
}

document.getElementById('bnModalClose').addEventListener('click', closeBnModal);
document.getElementById('bnModalBg').addEventListener('click', function(e){ if(e.target===this) closeBnModal(); });

/* Campaign row click → open detail modal */
document.addEventListener('click', function(e){
  var bnRow=e.target.closest('.bn-row');
  if(bnRow&&bnRow.dataset.bnId){ openBnModal(bnRow.dataset.bnId); return; }
  /* IP row inside campaign modal → open IP detail */
  var bnIpRow=e.target.closest('.bn-modal-ip-row');
  if(bnIpRow&&bnIpRow.dataset.ip){ closeBnModal(); toggleIpFocus(bnIpRow.dataset.ip); return; }
});

document.addEventListener('click',async function(e){
  /* Ban from audit log row — first click expands inline reason picker */
  var banBtn=e.target.closest('.audit-ban-btn');
  if(banBtn&&banBtn.dataset.ip){
    var ip=banBtn.dataset.ip;
    var wrap=banBtn.closest('.audit-ban-wrap');
    if(!wrap) return;
    var noteOpts='<option value="">— reason —</option>'
      +'<option value="http_abuse">HTTP abuse</option>'
      +'<option value="audit">Audit ban</option>'
      +'<option value="scanner">Scanner</option>'
      +'<option value="brute_force">Brute force</option>';
    wrap.innerHTML='<select class="ban-inp ban-note-sel audit-ban-note" style="max-width:115px;padding:2px 6px;font-size:10px;height:22px">'+noteOpts+'</select>'
      +'<button type="button" class="toolbtn danger audit-ban-confirm" data-ip="'+escapeAttr(ip)+'" style="font-size:9px;padding:2px 7px">Mute</button>'
      +'<button type="button" class="toolbtn audit-ban-cancel" style="font-size:9px;padding:2px 6px">✕</button>';
    wrap.querySelector('.audit-ban-note').focus();
    return;
  }

  /* Confirm mute from expanded audit row picker */
  var confirmBtn=e.target.closest('.audit-ban-confirm');
  if(confirmBtn&&confirmBtn.dataset.ip){
    var ip=confirmBtn.dataset.ip;
    var wrap=confirmBtn.closest('.audit-ban-wrap');
    var noteEl=wrap?wrap.querySelector('.audit-ban-note'):null;
    var note=noteEl?noteEl.value.trim():'';
    try{
      var body={ip:ip};
      if(note) body.note=note;
      var r=await fetch('/api/ban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      var j=await r.json().catch(function(){return{};});
      if(!r.ok){alert(j.error||'Mute failed');return;}
      warnIptables(j);
      await load(true);
      await loadAudit(true);
    }catch(err){alert('Mute failed');}
    return;
  }

  /* Cancel audit row picker */
  var cancelBtn=e.target.closest('.audit-ban-cancel');
  if(cancelBtn){
    var wrap=cancelBtn.closest('.audit-ban-wrap');
    if(wrap){
      var ip=wrap.querySelector('.audit-ban-confirm')?wrap.querySelector('.audit-ban-confirm').dataset.ip:'';
      if(ip){
        var isBanned=currentBannedSet.has(ip);
        wrap.innerHTML=isBanned
          ?'<button type="button" class="toolbtn audit-unban-btn" data-ip="'+escapeAttr(ip)+'" style="font-size:9px;padding:2px 7px">Unmute</button>'
          :'<button type="button" class="toolbtn danger audit-ban-btn" data-ip="'+escapeAttr(ip)+'" style="font-size:9px;padding:2px 7px">Mute</button>';
      }
    }
    return;
  }

  /* Unmute from audit log row */
  var unbanBtn=e.target.closest('.audit-unban-btn');
  if(unbanBtn&&unbanBtn.dataset.ip){
    var ip=unbanBtn.dataset.ip;
    try{
      var r=await fetch('/api/unban',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
      var j=await r.json().catch(function(){return{};});
      if(!r.ok){alert(j.error||'Unmute failed');return;}
      warnIptables(j);
      await load(true);
      await loadAudit(true);
    }catch(err){alert('Unmute failed');}
    return;
  }

  /* Delete TLS fingerprint cluster */
  var delBtn=e.target.closest('.tls-fp-del-btn');
  if(delBtn&&delBtn.dataset.fp){
    var fp=delBtn.dataset.fp;
    if(!confirm('Delete fingerprint cluster?\n\n'+fp+'\n\nThis removes the shared_tls_fp tag from all associated IPs.')) return;
    delBtn.disabled=true;
    try{
      var r=await fetch('/api/tls_fp/delete',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({fp:fp})});
      var j=await r.json().catch(function(){return{};});
      if(!r.ok){alert(j.error||'Delete failed');delBtn.disabled=false;return;}
      await load(true);
    }catch(err){alert('Delete failed');delBtn.disabled=false;}
    return;
  }
});

document.getElementById('btnClearAudit').addEventListener('click',async function(){
  if(!confirm('Clear all audit log entries? This cannot be undone.')) return;
  try{
    var r=await fetch('/api/audit',{method:'DELETE',credentials:'same-origin'});
    var j=await r.json().catch(function(){return{};});
    if(!r.ok){alert(j.error||'Clear failed');return;}
    auditLastCount=0;
    await loadAudit(true);
  }catch(err){alert('Clear failed');}
});

startAuditPoll();

/* ---- Settings modal ---- */
var settingsData=[];   // last fetched groups

function openSettings(){
  document.getElementById('settingsBg').classList.add('open');
  document.getElementById('settingsStatus').style.display='none';
  fetchSettings();
}
function closeSettings(){
  document.getElementById('settingsBg').classList.remove('open');
}

async function fetchSettings(){
  try{
    var r=await fetch('/api/settings',{credentials:'same-origin'});
    var j=await r.json();
    settingsData=j.groups||[];
    renderSettings(settingsData);
  }catch(e){
    document.getElementById('settingsBody').innerHTML='<div style="color:var(--danger);font-family:var(--mono);font-size:12px">Failed to load settings.</div>';
  }
}

function renderSettings(groups){
  var h='';
  groups.forEach(function(g){
    h+='<div class="settings-group">';
    h+='<div class="settings-group-title">'+escapeHtml(g.group)+'</div>';
    g.settings.forEach(function(s){
      var inputId='setting-'+s.key;
      var changed=s.value!==s.default;
      var inputHtml='';
      if(s.type==='bool'){
        inputHtml='<input type="checkbox" class="settings-input" id="'+inputId+'" data-key="'+escapeAttr(s.key)+'" data-type="bool"'+(s.value?' checked':'')+'/>';
      }else{
        inputHtml='<input type="number" class="settings-input'+(changed?' modified':'')+'" id="'+inputId+'"'
          +' data-key="'+escapeAttr(s.key)+'" data-type="'+escapeAttr(s.type)+'"'
          +' value="'+escapeAttr(String(s.value))+'"'
          +(s.min!=null?' min="'+s.min+'"':'')
          +(s.max!=null?' max="'+s.max+'"':'')+'/>';
      }
      h+='<div class="settings-row">';
      h+='<div><div class="settings-label">'+escapeHtml(s.label)+'</div><div class="settings-desc">'+escapeHtml(s.desc)+'</div></div>';
      h+=inputHtml;
      h+='<button class="settings-reset-btn" data-key="'+escapeAttr(s.key)+'" title="Reset to default">&#8635;</button>';
      h+='</div>';
    });
    h+='</div>';
  });
  document.getElementById('settingsBody').innerHTML=h;

  // Mark modified inputs on change
  document.querySelectorAll('.settings-input[type="number"]').forEach(function(inp){
    inp.addEventListener('input',function(){
      var key=inp.dataset.key;
      var orig=null;
      settingsData.forEach(function(g){g.settings.forEach(function(s){if(s.key===key)orig=s.default;});});
      var changed=parseFloat(inp.value)!==orig;
      inp.classList.toggle('modified',changed);
    });
  });
}

async function saveSettings(){
  var updates={};
  document.querySelectorAll('.settings-input').forEach(function(inp){
    var key=inp.dataset.key;
    if(!key) return;
    if(inp.type==='checkbox'){
      updates[key]=inp.checked;
    }else{
      updates[key]=inp.type==='number'?parseFloat(inp.value):inp.value;
    }
  });
  var statusEl=document.getElementById('settingsStatus');
  statusEl.style.display='';
  statusEl.className='settings-status-ok';
  statusEl.innerText='Saving...';
  try{
    var r=await fetch('/api/settings',{
      method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'set',updates:updates})
    });
    var j=await r.json();
    if(j.ok){
      settingsData=j.groups||settingsData;
      renderSettings(settingsData);
      statusEl.className='settings-status-ok';
      statusEl.innerText='Saved successfully.';
    }else{
      var errs=Object.entries(j.errors||{}).map(function(e){return e[0]+': '+e[1];}).join('; ');
      statusEl.className='settings-status-err';
      statusEl.innerText='Errors: '+errs;
    }
  }catch(e){
    statusEl.className='settings-status-err';
    statusEl.innerText='Save failed: '+e.message;
  }
}

async function resetAllSettings(){
  if(!confirm('Reset all settings to their environment/default values?')) return;
  var r=await fetch('/api/settings',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'reset_all'})
  });
  var j=await r.json();
  if(j.ok){
    settingsData=j.groups||settingsData;
    renderSettings(settingsData);
    var statusEl=document.getElementById('settingsStatus');
    statusEl.style.display='';
    statusEl.className='settings-status-ok';
    statusEl.innerText='All settings reset to defaults.';
  }
}

document.getElementById('settingsBg').addEventListener('click',function(e){
  if(e.target.id==='settingsBg') closeSettings();
});
document.getElementById('settingsClose').addEventListener('click',closeSettings);
document.getElementById('settingsSave').addEventListener('click',saveSettings);
document.getElementById('settingsResetAll').addEventListener('click',resetAllSettings);
document.getElementById('btnSettings').addEventListener('click',openSettings);

// Per-key reset button
document.getElementById('settingsBody').addEventListener('click',async function(e){
  var btn=e.target.closest('.settings-reset-btn');
  if(!btn) return;
  var key=btn.dataset.key;
  var r=await fetch('/api/settings',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'reset_one',key:key})
  });
  var j=await r.json();
  if(j.ok){settingsData=j.groups||settingsData;renderSettings(settingsData);}
});

document.addEventListener('keydown',function(e){
  if(e.key==='Escape'&&document.getElementById('settingsBg').classList.contains('open')){
    closeSettings();
  }
});

setPoll(1500);
load();
refreshHistory();
