// NETCONF <hello> message
#define NETCONF_HELLO_MSG \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" \
    "  <capabilities>\n" \
    "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n" \
    "  </capabilities>\n" \
    "</hello>]]>]]>"

#define NETCONF_GET_CONFIG_MSG \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"10\">\n" \
    "  <get-config>\n" \
    "    <source>\n" \
    "      <running/>\n" \
    "    </source>\n" \
    "  </get-config>\n" \
    "</rpc>]]>]]>"

#define NETCONF_GET_STATE \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"10\">\n" \
    "  <get>" \
    "    <filter type=\"subtree\">" \
    "      <interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\"/>" \
    "    </filter>" \
    "  </get>" \
    "</rpc>]]>]]>"

// NETCONF <close-session> message
#define NETCONF_CLOSE_SESSION_MSG \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<rpc message-id=\"9999\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" \
    "  <close-session/>\n" \
    "</rpc>]]>]]>"
