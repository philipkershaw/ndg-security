##################################################
# Gatekeeper_services_server.py
#      Generated by ZSI.generate.wsdl2dispatch.DelAuthServiceModuleWriter
#
##################################################

from Gatekeeper_services import *
from ZSI.ServiceContainer import ServiceSOAPBinding

class GatekeeperService(ServiceSOAPBinding):
    soapAction = {}
    root = {}
    _wsdl = """<?xml version=\"1.0\" ?>
<wsdl:definitions name=\"Gatekeeper\" targetNamespace=\"ndg:security:Gatekeeper\" xmlns=\"http://schemas.xmlsoap.org/wsdl/\" xmlns:http=\"http://schemas.xmlsoap.org/wsdl/http/\" xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:tns=\"ndg:security:Gatekeeper\" xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\" xmlns:wsu=\"http://schemas.xmlsoap.org/ws/2002/07/utility\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">

  <wsdl:types>
    <xsd:schema>
      <xsd:element name=\"get\">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element maxOccurs=\"1\" minOccurs=\"1\" name=\"userX509Cert\" type=\"xsd:string\"/>
            <xsd:element maxOccurs=\"1\" minOccurs=\"1\" name=\"userAttributeCertificate\" type=\"xsd:string\"/>
            <xsd:element maxOccurs=\"1\" minOccurs=\"1\" name=\"geoserverRequest\" type=\"xsd:string\"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name=\"getResponse\">
        <xsd:complexType>
		  <xsd:sequence>
	        <xsd:element maxOccurs=\"1\" minOccurs=\"1\" name=\"geoServerResponse\" type=\"xsd:string\"/>
		  </xsd:sequence>
		</xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </wsdl:types>

  <wsdl:message name=\"getInputMsg\">
    <wsdl:part element=\"get\" name=\"parameters\"/>
  </wsdl:message>

  <wsdl:message name=\"getOutputMsg\">
    <wsdl:part element=\"getResponse\" name=\"parameters\"/>
  </wsdl:message>

  <wsdl:portType name=\"Gatekeeper\">
    <wsdl:operation name=\"get\">
      <wsdl:input message=\"tns:getInputMsg\"/>
      <wsdl:output message=\"tns:getOutputMsg\"/>
    </wsdl:operation>
  </wsdl:portType>

  <wsdl:binding name=\"GatekeeperBinding\" type=\"tns:Gatekeeper\">
    <soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>
    <wsdl:operation name=\"get\">
      <soap:operation soapAction=\"get\"/>
      <wsdl:input>
        <soap:body use=\"literal\"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use=\"literal\"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>

  <wsdl:service name=\"GatekeeperService\">
    <wsdl:documentation>DEWS Gatekeeper web service</wsdl:documentation>
    <wsdl:port binding=\"tns:GatekeeperBinding\" name=\"Gatekeeper\">
      <soap:address location=\"http://localhost:5000\"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>"""

    def __init__(self, post='', **kw):
        ServiceSOAPBinding.__init__(self, post)
        if kw.has_key('impl'):
            self.impl = kw['impl']
        self.auth_method_name = None
        if kw.has_key('auth_method_name'):
            self.auth_method_name = kw['auth_method_name']
    def authorize(self, auth_info, post, action):
        if self.auth_method_name and hasattr(self.impl, self.auth_method_name):
            return getattr(self.impl, self.auth_method_name)(auth_info, post, action)
        else:
            return 1

    def soap_get(self, ps):
        self.request = ps.Parse(getInputMsg.typecode)
        parameters = (self.request._userX509Cert, self.request._userAttributeCertificate, self.request._geoserverRequest)

        # If we have an implementation object use it
        if hasattr(self,'impl'):
            parameters = self.impl.get(parameters[0],parameters[1],parameters[2])

        result = getOutputMsg()
        # If we have an implementation object, copy the result 
        if hasattr(self,'impl'):
            result._geoServerResponse = parameters
        return result

    soapAction['get'] = 'soap_get'
    root[(getInputMsg.typecode.nspname,getInputMsg.typecode.pname)] = 'soap_get'

