"use strict";function saveProject(){r2.cmd("Ps",function(){alert("Project saved")})}function deleteProject(){alert("Project deleted"),location.href="open.html"}function closeProject(){alert("Project closed"),location.href="open.html"}function write(){var e=prompt("hexpairs, quoted string or :assembly");if(""!=e)switch(e[0]){case":":e=e.substring(1),r2.cmd('"wa '+e+'"',update);break;case'"':e=e.replace(/"/g,""),r2.cmd("w "+e,update);break;default:r2.cmd("wx "+e,update)}}function comment(){var e=prompt("comment");e&&("-"===e?r2.cmd("CC-"):r2.cmd('"CC '+e+'"'),update())}function flag(){var e=prompt("flag");e&&("-"===e?r2.cmd("f"+e):r2.cmd("f "+e),update())}function block(){var e=prompt("block");e&&e.trim()&&(r2.cmd("b "+e),update())}function flagsize(){var e=prompt("size");e&&e.trim()&&(r2.cmd("fl $$ "+e),update())}function E(e){return document.getElementById(e)}function encode(e){return e.replace(/[\x26\x0A\<>'"]/g,function(e){return"&#"+e.charCodeAt(0)+";"})}function clickableOffsets(e){return console.error("Using clickableOffsets(str) no longer work"),console.trace(),e=e.replace(/0x([a-zA-Z0-9]*)/g,"<a href='javascript:seek(\"0x$1\")'>0x$1</a>"),e=e.replace(/sym\.([\.a-zA-Z0-9_]*)/g,"<a href='javascript:seek(\"sym.$1\")'>sym.$1</a>"),e=e.replace(/fcn\.([\.a-zA-Z0-9_]*)/g,"<a href='javascript:seek(\"fcn.$1\")'>fcn.$1</a>"),e=e.replace(/str\.([\.a-zA-Z0-9_]*)/g,"<a href='javascript:seek(\"str.$1\")'>str.$1</a>")}function uiButton(e,t,a){var n="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ";if("active"===a){return'&nbsp;<a href="'+e.replace(/"/g,"'")+'" class="'+n+'" style="background-color:#f04040 !important">'+t+"</a>"}return'&nbsp;<a href="'+e.replace(/"/g,"'")+'" class="'+n+'">'+t+"</a>"}function uiCheckList(e,t,a){var n="<li>";return n+='<label for="'+e+'" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">',n+='<input type="checkbox" id="'+t+'" class="mdl-checkbox__input" />',n+='<span class="mdl-checkbox__label">'+a+"</span>",n+="</label></li>"}function uiCombo(d){var funName="combo"+ ++comboId,fun=funName+" = function(e) {";fun+=' var sel = document.getElementById("opt_'+funName+'");',fun+=" var opt = sel.options[sel.selectedIndex].value;",fun+=" switch (opt) {";for(var a in d)fun+='case "'+d[a].name+'": '+d[a].js+"("+d[a].name+");break;";fun+="}}",eval(fun);var out='<select id="opt_'+funName+'" onchange="'+funName+'()">';for(var a in d){var def=d[a].default?" default":"";out+="<option"+def+">"+d[a].name+"</option>"}return out+="</select>"}function uiSwitch(e,t,a,n){var s="switch-"+ ++idSwitch,o=document.createElement("label");o.className="mdl-switch mdl-js-switch mdl-js-ripple-effect",o.for=s,e.appendChild(o);var l=document.createElement("input");l.type="checkbox",l.className="mdl-switch__input",l.checked=a,l.id=s,o.appendChild(l),l.addEventListener("change",function(e){n(t,e.target.checked)});var r=document.createElement("span");r.className="mdl-switch__label",r.innerHTML=t,o.appendChild(r);var c=document.createElement("br");o.appendChild(c)}function uiActionButton(e,t,a){var n=document.createElement("a");n.href="#",n.innerHTML=a,n.addEventListener("click",t),e.appendChild(n);var s="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect ";s+="mdl-color--accent mdl-color-text--accent-contrast",n.className=s,n.style.margin="3px"}function uiSelect(e,t,a,n,s){var o="select-"+ ++selectId,l=document.createElement("div");l.className="mdl-selectfield mdl-js-selectfield mdl-selectfield--floating-label",e.appendChild(l);var r=document.createElement("select");r.className="mdl-selectfield__select",r.id=o,r.name=o,l.appendChild(r);for(var c=0;c<a.length;c++){var d=document.createElement("option");d.innerHTML=a[c],d.value=a[c],r.appendChild(d),c===n&&(d.selected=!0)}r.addEventListener("change",function(e){s(e.target.value)});var i=document.createElement("label");i.className="mdl-selectfield__label",i.for=o,i.innerHTML=t,l.appendChild(i)}function uiBlock(e){var t="";for(var a in e.blocks){var n=e.blocks[a];t+="<br />"+n.name+": ",t+=uiCombo(n.buttons)}return t}function uiRoundButton(e,t,a){var n="";return n+="<button onclick="+e+' class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect" '+a+">",n+='<i class="material-icons" style="opacity:1">'+t+"</i>",n+="</button>"}function uiTableBegin(e,t){console.warn("Usage is deprecated: migrate to Table");var a="";a+='<table id="'+(t||"").substr(1)+'" style="margin-left:10px" class="mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp">',a+="  <thead> <tr>";var n;for(var s in e){var o=e[s];"+"===o[0]?(o=o.substring(1),n=""):n=' class="mdl-data-table__cell--non-numeric"',a+="<th"+n+">"+o+"</th>"}return a+="</tr> </thead> <tbody>"}function uiTableRow(e){var t="",a="<tr>";for(var n in e){var s=e[n];s&&("+"===s[0]?s=clickableOffsets(s.substring(1)):t=' class="mdl-data-table__cell--non-numeric"',a+="<td"+t+">"+s+"</td>")}return a+"</tr>"}function uiTableEnd(){return"</tbody> </table>"}function console_submit(e){var t=(document.getElementById("console_terminal"),document.getElementById("console_output")),a=document.getElementById("console_input"),n=widgetContainer.getWidget("Console");widgetContainer.getWidgetDOMWrapper(n);if("clear"===e)return t.innerHTML="",void(a.value="");r2.cmd(e,function(n){t.innerHTML+=" > "+e+"\n"+n,a.value="",setTimeout(function(){window.scrollTo("console_input")},1e3)})}function console_ready(){var e=document.getElementById("console_input");null!==e&&(r2.cmd("e scr.color=true"),e.focus(),e.onkeypress=function(t){13===t.keyCode&&console_submit(e.value)})}function consoleKey(e){var t=document.getElementById("console_input");e?13===e.keyCode&&(runCommand(t.value),t.value=""):t.onkeypress=consoleKey}function panelConsole(){var e=widgetContainer.getWidget("Console"),t=widgetContainer.getWidgetDOMWrapper(e);updates.registerMethod(e.getOffset(),panelConsole);t.innerHTML='<br /><div id="console_terminal" class="console_terminal"><div id="console_output" class=console_output></div><div id="console_prompt" class=console_prompt>&nbsp;&gt;&nbsp;<input name="console_input" class="console_input" id="console_input"></input></div></div><br /><br />',t.style.backgroundColor="#303030",t.style.height="100%",document.getElementById("console_output").innerHTML=lastConsoleOutput,console_ready()}function runCommand(e){e||(e=document.getElementById("input").value),r2.cmd(e,function(e){lastConsoleOutput="\n"+e,document.getElementById("output").innerHTML=lastConsoleOutput})}function setStatusbarBody(){function e(e,t){var a=document.createElement(e);return a.id=t,a.className=t,a}var t;try{var a=document.getElementById("tab_terminal");a.innerHTML="",a.parentNode.removeChild(a)}catch(e){}try{var a=document.getElementById("tab_logs");a.innerHTML="",a.parentNode.removeChild(a)}catch(e){}switch(statusTab){case Tab.LOGS:var n=new DOMParser,t=document.createElement("div");t.id="tab_logs";var s=statusLog.join("<br />");t.appendChild(n.parseFromString(s,"text/xml").documentElement);var a=document.getElementById("statusbar_body");try{a.parentNode.insertBefore(t,a)}catch(e){}return void console.log(a);case Tab.CONSOLE:var t=document.createElement("div");t.id="tab_terminal",t.appendChild(e("div","terminal")),t.appendChild(e("div","terminal_output"));var o=e("div","terminal_prompt");o.appendChild(e("input","terminal_input")),t.appendChild(o)}if(void 0!==t){var a=document.getElementById("statusbar");document.getElementById("terminal")||(a.parentNode.insertBefore(t,a),statusTab===Tab.CONSOLE&&terminal_ready())}}function statusMessage(e,t){var a=document.getElementById("statusbar");e&&statusLog.push(e),statusMode===Mode.LINE?(a.innerHTML=e,null!==statusTimeout&&(clearTimeout(statusTimeout),statusTimeout=null),void 0!==t&&(statusTimeout=setTimeout(function(){statusMessage("&nbsp;")},1e3*t))):setStatusbarBody()}function statusToggle(){var e=document.getElementById("statusbar"),t=document.getElementById("container");if(statusMode===Mode.HALF){statusTab=Tab.LOGS,statusMode=Mode.LINE,e.innerHTML="&nbsp;";try{e.parentNode.classList.remove("half"),e.parentNode.classList.remove("full"),t.classList.remove("sbIsHalf"),t.classList.remove("sbIsFull")}catch(e){}setStatusbarBody()}else{statusMode=Mode.HALF;try{e.parentNode.classList.remove("full"),t.classList.remove("sbIsFull")}catch(e){}e.parentNode.classList.add("half"),t.classList.add("sbIsHalf")}}function statusNext(){var e=document.getElementById("statusbar"),t=document.getElementById("container");switch(statusMode){case Mode.LINE:statusMode=Mode.HALF;try{e.parentNode.classList.remove("full"),t.classList.remove("sbIsFull")}catch(e){}e.parentNode.classList.add("half"),t.classList.add("sbIsHalf");break;case Mode.HALF:return statusMode=Mode.FULL,e.parentNode.classList.add("full"),void t.classList.add("sbIsFull");case Mode.FULL:statusMode=Mode.LINE,statusTab=Tab.LOGS,e.innerHTML="";try{var e=document.getElementById("statusbar"),t=document.getElementById("container");e.parentNode.classList.remove("half"),e.parentNode.classList.remove("full"),t.classList.remove("sbIsHalf"),t.classList.remove("sbIsFull")}catch(e){}}setStatusbarBody()}function statusConsole(){var e=document.getElementById("statusbar"),t=document.getElementById("container");if(statusTab===Tab.CONSOLE){if(statusMode!==Mode.LINE)return statusToggle(),void(statusMode=Mode.LINE);statusTab=Tab.CONSOLE}if(statusMode===Mode.HALF)statusMode=Mode.LINE;else if(statusMode===Mode.LINE){statusTab=Mode.CONSOLE,statusMode=Mode.HALF;try{e.parentNode.classList.remove("full"),t.classList.remove("sbIsFull")}catch(e){}try{e.parentNode.classList.add("half"),t.classList.add("sbIsHalf")}catch(e){}}statusTab=statusTab===Tab.CONSOLE?Tab.LOGS:Tab.CONSOLE,setStatusbarBody()}function statusFullscreen(){var e=document.getElementById("statusbar"),t=document.getElementById("container");if(statusMode===Mode.FULL){statusMode=Mode.HALF;try{e.parentNode.classList.remove("full"),t.classList.remove("sbIsFull")}catch(e){}e.parentNode.classList.add("half"),t.classList.add("sbIsHalf")}else{statusMode=Mode.FULL;try{e.parentNode.classList.remove("half"),t.classList.remove("sbIsHalf")}catch(e){}e.parentNode.classList.add("full"),t.classList.add("sbIsFull")}}function addButton(e,t){var a=document.createElement("a");return a.href="javascript:"+t+"()",a.innerHTML=e,a}function initializeStatusbarTitle(){return}function statusInitialize(){initializeStatusbarTitle();var e=document.getElementById("statusbar");e.innerHTML="",e.parentNode.addEventListener("click",function(){statusMode===Mode.LINE&&(statusTab=Tab.CONSOLE,statusToggle())}),statusMessage("Loading webui...",2)}function submit(e){var t=document.getElementById("terminal_output"),a=document.getElementById("terminal_input");return a&&t?"clear"===e?(t.innerHTML="",void(a.value="")):void r2.cmd(e,function(n){n+="\n",t.innerHTML+=" > "+e+"\n"+n,a.value="";var s=document.getElementById("statusbar_scroll");s.scrollTop=s.scrollHeight}):void console.error("No terminal_{input|output} found")}function terminal_ready(){r2.cmd("e scr.color=true");var e=document.getElementById("terminal_input");if(!e)return void console.error("Cannot find terminal_input");e.focus(),e.onkeypress=function(t){13===t.keyCode&&submit(e.value)}}function hexPairToASCII(e){var t=parseInt(e,16);return t>=33&&t<=126?String.fromCharCode(t):"."}function ASCIIToHexpair(e){var t=e.charCodeAt(0).toString(16);return t.length<2&&(t="0"+t),t}function isAsciiVisible(e){return e>=33&&e<=126}function basename(e){return e.split(/[\\\/]/).pop()}function int2fixedHex(e,t){for(var a=e.toString(16);a.length<t;)a="0"+a;return"0x"+a}!function(){function e(){s++,r2.cmdj("?V",function(e){void 0!==e&&(s=0)})}function t(){if(s>0){for(var e=document.getElementsByClassName("first-attempt"),t=0;t<e.length;t++)e[t].style.display="none";for(var a=document.getElementsByClassName("next-attempt"),t=0;t<a.length;t++)a[t].style.display="block"}}var a=document.getElementById("networkerr"),n=!1,s=0;a.showModal||dialogPolyfill.registerDialog(a),a.querySelector(".retry").addEventListener("click",function(){a.close(),e(),n=!1}),a.querySelector(".close").addEventListener("click",function(){a.close(),n=!1}),a.querySelector(".ok").addEventListener("click",function(){a.close(),n=!1}),r2.err=function(){n||(t(),a.showModal())}}();var comboId=0,idSwitch=0,selectId=0,lastConsoleOutput="",statusLog=[],Mode={LINE:0,HALF:1,FULL:2},Tab={LOGS:0,CONSOLE:1},statusMode=Mode.LINE,statusTimeout=null,statusTab=Tab.LOGS;statusInitialize();