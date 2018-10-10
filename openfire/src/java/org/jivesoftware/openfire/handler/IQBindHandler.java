/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.handler;

import gnu.inet.encoding.StringprepException;

import org.dom4j.Element;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.RoutingTable;
import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.AuthToken;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.event.SessionEventDispatcher;
import org.jivesoftware.openfire.session.ClientSession;
import org.jivesoftware.openfire.session.LocalClientSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.PacketError;
import org.xmpp.packet.StreamError;

/**
 *	将资源绑定到流，以便客户机的地址变成完整的JID。资源被绑定到会话，实体(即客户端)一次就被认为是一个连接的资源
 *	<p>
 *	客户机可以指定所需的资源，但如果没有指定资源，则服务器将为会话创建一个随机资源。
 * 	新的资源应该与ResourcePrep一致。
 * 	服务器还将验证是否有来自同一用户，使用用户指定的资源的先前会话。
 * 	根据服务器配置的不同，旧会话可能被踢出，或者新会话可能被拒绝。
 * 	</p>
 *
 * @author Gaston Dombiak
 */
public class IQBindHandler extends IQHandler {

    private static final Logger Log = LoggerFactory.getLogger(IQBindHandler.class);

    private IQHandlerInfo info;
    private String serverName;
    private RoutingTable routingTable;

    public IQBindHandler() {
        super("Resource Binding handler");
        info = new IQHandlerInfo("bind", "urn:ietf:params:xml:ns:xmpp-bind");
    }

    @Override
    public IQ handleIQ(IQ packet) throws UnauthorizedException {
        LocalClientSession session = (LocalClientSession) sessionManager.getSession(packet.getFrom());
        // If no session was found then answer an error (if possible)
        if (session == null) {
            Log.error("Error during resource binding. Session not found in " +
                    sessionManager.getPreAuthenticatedKeys() +
                    " for key " +
                    packet.getFrom());
            // This error packet will probably won't make it through
            IQ reply = IQ.createResultIQ(packet);
            reply.setChildElement(packet.getChildElement().createCopy());
            reply.setError(PacketError.Condition.internal_server_error);
            return reply;
        }

        IQ reply = IQ.createResultIQ(packet);
        Element child = reply.setChildElement("bind", "urn:ietf:params:xml:ns:xmpp-bind");
        // Check if the client specified a desired resource
        String resource = packet.getChildElement().elementTextTrim("resource");
        if (resource == null || resource.length() == 0) {
            // None was defined so use the random generated resource
            resource = session.getAddress().getResource();
        }
        else {
            // Check that the desired resource is valid
            try {
                resource = JID.resourceprep(resource);
            }
            catch (StringprepException e) {
                reply.setChildElement(packet.getChildElement().createCopy());
                reply.setError(PacketError.Condition.jid_malformed);
                // Send the error directly since a route does not exist at this point.
                session.process(reply);
                return null;
            }
        }
        // Get the token that was generated during the SASL authentication
        AuthToken authToken = session.getAuthToken();
        if (authToken == null) {
            // User must be authenticated before binding a resource
            reply.setChildElement(packet.getChildElement().createCopy());
            reply.setError(PacketError.Condition.not_authorized);
            // Send the error directly since a route does not exist at this point.
            session.process(reply);
            return reply;
        }
        if (authToken.isAnonymous()) {
            // User used ANONYMOUS SASL so initialize the session as an anonymous login
            session.setAnonymousAuth();
        }
        else {
            String username = authToken.getUsername().toLowerCase();
            // If a session already exists with the requested JID, then check to see
            // if we should kick it off or refuse the new connection
            ClientSession oldSession = routingTable.getClientRoute(new JID(username, serverName, resource, true));
            if (oldSession != null) {
                try {
                    int conflictLimit = sessionManager.getConflictKickLimit();
                    if (conflictLimit == SessionManager.NEVER_KICK) {
                        reply.setChildElement(packet.getChildElement().createCopy());
                        reply.setError(PacketError.Condition.conflict);
                        // Send the error directly since a route does not exist at this point.
                        session.process(reply);
                        return null;
                    }

                    int conflictCount = oldSession.incrementConflictCount();
                    if (conflictCount > conflictLimit) {
                        Log.debug( "Kick out an old connection that is conflicting with a new one. Old session: {}", oldSession );
                        StreamError error = new StreamError(StreamError.Condition.conflict);
                        oldSession.deliverRawText(error.toXML());
                        oldSession.close();
                    }
                    else {
                        reply.setChildElement(packet.getChildElement().createCopy());
                        reply.setError(PacketError.Condition.conflict);
                        // Send the error directly since a route does not exist at this point.
                        session.process(reply);
                        return null;
                    }
                }
                catch (Exception e) {
                    Log.error("Error during login", e);
                }
            }
            // If the connection was not refused due to conflict, log the user in
            session.setAuthToken(authToken, resource);
        }

        child.addElement("jid").setText(session.getAddress().toString());
        // Send the response directly since a route does not exist at this point.
        session.process(reply);
        // After the client has been informed, inform all listeners as well.
        SessionEventDispatcher.dispatchEvent(session, SessionEventDispatcher.EventType.resource_bound);
        return null;
    }

    @Override
    public void initialize(XMPPServer server) {
        super.initialize(server);
        routingTable = server.getRoutingTable();
        serverName = server.getServerInfo().getXMPPDomain();
     }

    @Override
    public IQHandlerInfo getInfo() {
        return info;
    }
}
