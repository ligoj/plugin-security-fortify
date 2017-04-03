









<script type="javascript">
	var defaultTitle = 'HP Fortify Software Security Center';
</script>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
	<head>
		<title>HP Fortify Software Security Center</title>
		<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
        <link rel="shortcut icon" type="image/png" href="../images/favicon.ico"/>
		<style id="antiClickjack">body{display:none !important;}</style>
		<script type="text/javascript">
			if (self === top) {
				var antiClickjack = document.getElementById("antiClickjack");
				antiClickjack.parentNode.removeChild(antiClickjack);
			} else {
				top.location = self.location;
			}
		</script>
		<script type="text/javascript">if (top!=self) top.location.href=self.location.href;</script>

		<style type="text/css" media="screen">
			/*REGULAR*/
			@font-face {
				font-family: 'HPSimplified';
				src: url(../html/themes/evo/fonts/latin-e-regular-eot.eot);
				/* IE9 compat */
				src: url(../html/themes/evo/fonts/latin-e-regular-eot.eot?#iefix) format("embedded-opentype"), url
(../html/themes/evo/fonts/latin-e-regular-woff.woff) format("-woff.woff"), url(../html/themes/evo/fonts
/latin-e-regular-ttf.ttf) format("truetype");
				/*iOS, Android, Safari*/
				font-weight: normal;
				font-style: normal;
			}

			/*BOLD*/
			@font-face {
				font-family: 'HPSimplified';
				src: url(../html/themes/evo/fonts/latin-e-bold-eot.eot);
				/* IE9 compat */
				src: url(../html/themes/evo/fonts/latin-e-bold-eot.eot?#iefix) format("embedded-opentype"), url(
../html/themes/evo/fonts/latin-e-bold-woff.woff) format("-woff.woff"), url(../html/themes/evo/fonts/latin-e-bold-ttf
.ttf) format("truetype");
				/*iOS, Android, Safari*/
				font-weight: bold;
				font-style: normal;
			}

			html, body, #flexContent, { height:100%; background-color:#FFFFFF; }
			body { font-family: HPSimplified,Helvetica,Helvetica,Arial,sans-serif;margin:0; padding:0; overflow
:hidden; }
			.alert {
				display: none;
				z-index: 5000;
				right: 0px;
				left: 0px;
				position: absolute;
				top: 0px;
				color: #C09853;
				-webkit-border-radius: 0;
				-moz-border-radius: 0;
				border-radius: 0;
				padding: 2px 35px 2px 14px;
				margin-bottom: 20px;
				text-shadow: 0 1px 0 rgba(255, 255, 255, 0.5);
				background-color: #FCF8E3;
				border: 1px solid #FBEED5;
			}
			.close {
				padding: 0;
				cursor: pointer;
				background: 0 0;
				border: 0;
				-webkit-appearance: none;
				font-size: 15px;
				font-weight: 700;
				color: #000;
				text-shadow: 0 1px 0 #FFF;
				opacity: .2;
				position: absolute;
				right: 15px;
				line-height: 20px;
				margin: 0px;
				vertical-align: middle;
			}
		</style>
		<!--  BEGIN Browser History required section -->
		<link rel="stylesheet" type="text/css" href="history/history.css"/>
		<script src="history/history.js" language="javascript"></script>
		<!--  END Browser History required section -->
		<script type="text/javascript" src="swfobject.js"></script>
		<script type="text/javascript" src="../scripts/jquery/jquery.min.js"></script>
		<script type="text/javascript">
    var flashvars = {};
		flashvars.locale="fr";flashvars.scheme="https";flashvars.serverName="delivery.gfi.fr";flashvars.serverPort
="443";flashvars.contextRoot="/ssc";

		var params = {
			quality: "high",
			bgcolor: "#FFFFFF",
			allowscriptaccess: "sameDomain",
			align: "middle",
			allowfullscreen: "true",
			wmode: "opaque"
		};

	  var attributes = {};
	    var config = {
		    dataType: "json",
		    headers: {
			    Authorization: 'FortifyToken MGQ4NjVmOTktODc0ZS00NGUwLTkzZGYtMDZjNzExNDk4MGQ1'
		    },
		    url: "/ssc"+ '/api/v1/applicationState',
		    success: function success(result){
			    console.log(result);
			    if(result && result.data && result.data.configVisitRequired){
				    $('.alert').show();
			    }
		    }
	    };
	    $(function ready(){
		    $('.close').click(function close(){
			    $('.alert').hide();
		    });
		    $('#btnGotoConfig').click(function goToConfig(){
			    $('.alert').hide();
			    window.open('/ssc/html/ssc/index.jsp#!/admin/configuration/core','_blank');
		    });
	    });
    $.ajax(config);
		swfobject.embedSWF("ssc.swf?swfChecksum=325f6376eddca23b572643e465b6a197", "flexContent", "100%", "100
%", "10.2.0", "expressInstall.swf", flashvars, params, attributes);
		</script>
	</head>

	<body>
		<div id="flexContent">
			<p>HP Fortify Software Security Center requires the Adobe Flash Player.</p>
			<p><a href="https://www.adobe.com/go/getflashplayer"><img src="https://www.adobe.com/images/shared
/download_buttons/get_flash_player.gif" alt="Get Flash" /></a></p>
		</div>
		<div class="alert"><span><span>This is either a fresh installation or a newly migrated instance of
 Software Security Center. Please see the Configuration section on the Administration page.&nbsp;</span
></span><a id="btnGotoConfig" href="javascript:void(0);">Go...</a><button id="btnCloseMsgDlg" class="close"
>x</button></div>
	</body>
</html>