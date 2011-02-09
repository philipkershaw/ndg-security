<html py:extends="'ndgPage.kid'" xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#">
    
    <div py:def="loginForm()" class="loginForm">
        <form action="$g.ndg.security.server.sso.cfg.getCredentials" method="POST">
            <table cellspacing="0" border="0" cellpadding="5">
                <tr>
                    <td>Username:</td> 
                    <td><input type="text" name="username" value=""/></td>
                </tr><tr>
                    <td>Pass-phrase:</td>
                    <td><input type="password" name="passphrase"/></td>
                </tr><tr>
                    <td colspan="2" align="right">
                    	<input type="submit" value="Login"/>
                    </td>
                </tr>
            </table>
        </form>
    </div>
    
    <head>
    <replace py:replace="pagehead()"/>
    </head>
    <body>
        <div py:replace="header()"/>
        <div class="loginContent" style="text-indent:5px">        
            <h4>Login</h4>
            <div py:replace="loginForm()"/>
            <p>${c.xml}</p>
        </div>
        <div py:replace="footer(showLoginStatus=False)"/>
    </body>

</html>