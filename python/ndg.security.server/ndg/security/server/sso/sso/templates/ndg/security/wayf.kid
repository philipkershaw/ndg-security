<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    <div py:if="len(g.ndg.security.server.sso.state.trustedIdPs) > 0" py:def="trustedSitesList()" class="trustedSitesList" style="text-indent:5px">        
        <h4> Where are you from? </h4>
        <p> You can login in at a trusted partner site:
	        <?python
	        # Sort alphabetically
	        providerNames = g.ndg.security.server.sso.state.trustedIdPs.keys()
	        providerNames.sort()
	        ?>
	        <ul py:for="h in providerNames">
	            <li> <a href="${g.ndg.security.server.sso.state.trustedIdPs[h]}?r=${g.ndg.security.common.sso.state.b64encReturnToURL}">${h}</a></li>
	        </ul>
	    </p>
		<p>Alternatively, sign in with OpenID:</p>
	</div>
    <div py:if="len(g.ndg.security.server.sso.state.trustedIdPs) == 0" py:def="trustedSitesListNotAvailable()" class="trustedSitesListNotAvailable" style="text-indent:5px">        
		<h4>Where are you from?</h4>
	</div>
    <div py:def="openIDSignin()" class="openIDSignin" style="text-indent:5px">
		<form action="$g.ndg.security.server.sso.cfg.server/verify" method="post">
		  <table cellspacing="0" border="0" cellpadding="5">
		    <tr>
		        <td>OpenID:</td> 
		        <td>
		        	<input type="text" name="openid" value="" class='openid-identifier'/>
		        </td>
		        <td align="right">
		        	<input type="submit" name="authform" value="Go"/>
		        </td>
		        <td>
		        	<a href="http://openid.net/what/" target="_blank"><small>What's this?</small></a>
		        </td>
		    </tr>
		  </table>
		</form>
	</div>

    <head>
  		<style>
			input.openid-identifier {
			   background: url($g.ndg.security.server.sso.cfg.server/layout/openid-inputicon.gif) no-repeat;
			   background-color: #fff;
			   background-position: 0 50%;
			   padding-left: 18px;
			}
  		</style>
    	<replace py:replace="pagehead()"/>
    </head>
    <body>
        <div py:replace="header()"/>
        <replace py:replace="trustedSitesList()"/>
        <replace py:replace="trustedSitesListNotAvailable()"/>
    	<replace py:replace="openIDSignin()"/>
        <div py:replace="footer(showLoginStatus=False)"/>
    </body>
</html>