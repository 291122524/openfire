/*
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
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

package org.jivesoftware.openfire;

import org.dom4j.Document;
import org.dom4j.io.SAXReader;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.admin.AdminManager;
import org.jivesoftware.openfire.audit.AuditManager;
import org.jivesoftware.openfire.audit.spi.AuditManagerImpl;
import org.jivesoftware.openfire.auth.ScramUtils;
import org.jivesoftware.openfire.cluster.ClusterManager;
import org.jivesoftware.openfire.cluster.NodeID;
import org.jivesoftware.openfire.commands.AdHocCommandHandler;
import org.jivesoftware.openfire.component.InternalComponentManager;
import org.jivesoftware.openfire.container.AdminConsolePlugin;
import org.jivesoftware.openfire.container.Module;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.disco.*;
import org.jivesoftware.openfire.filetransfer.DefaultFileTransferManager;
import org.jivesoftware.openfire.filetransfer.FileTransferManager;
import org.jivesoftware.openfire.filetransfer.proxy.FileTransferProxy;
import org.jivesoftware.openfire.handler.*;
import org.jivesoftware.openfire.keystore.CertificateStoreManager;
import org.jivesoftware.openfire.keystore.IdentityStore;
import org.jivesoftware.openfire.lockout.LockOutManager;
import org.jivesoftware.openfire.mediaproxy.MediaProxyService;
import org.jivesoftware.openfire.muc.MultiUserChatManager;
import org.jivesoftware.openfire.net.MulticastDNSService;
import org.jivesoftware.openfire.net.ServerTrafficCounter;
import org.jivesoftware.openfire.pep.IQPEPHandler;
import org.jivesoftware.openfire.pep.IQPEPOwnerHandler;
import org.jivesoftware.openfire.pubsub.PubSubModule;
import org.jivesoftware.openfire.roster.RosterManager;
import org.jivesoftware.openfire.session.RemoteSessionLocator;
import org.jivesoftware.openfire.spi.*;
import org.jivesoftware.openfire.transport.TransportHandler;
import org.jivesoftware.openfire.update.UpdateManager;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.vcard.VCardManager;
import org.jivesoftware.util.*;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.io.*;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * XMPP主服务器将加载、初始化和启动所有服务器模块。 主服务器在JVM中是唯一的，可以使用getInstance()方法获取。
 * <p>
 *	加载的模块将被初始化，可以通过服务器其他模块访问。
 *	这意味着一个模块定位另一个模块的唯一方法是通过服务器。
 *	服务器维护已一个已加载模块的List。
 * </p>
 * <p>
 *	启动所有模块后，服务器将加载任何可用插件。
 * For more information see: {@link org.jivesoftware.openfire.container.PluginManager}.
 * </p>
 * <p>配置文件保存服务器配置。 服务器正常工作需要配置文件。
 *	服务器假定配置文件已经命名为openfire.xml,位于conf文件夹中。
 *	保存配置文件的文件夹必须位于主文件夹下。 服务器将尝试不同的方法查找主文件夹。
 * </p>
 * <ol>
 * <li><b>system property</b> - 服务器将使用系统属性<i>openfireHome</i>中定义的值。</li>
 * <li><b>working folder</b> -  在独立模式下运行时服务器将检查在工作目录下是否有conf文件夹。</li>
 * <li><b>openfire_init.xml 文件</b> - 尝试从openfire_init.xml加载值,该文件必须在类路径中</li>
 * </ol>
 *
 * @author Gaston Dombiak
 */
public class XMPPServer {

    private static final Logger logger = LoggerFactory.getLogger(XMPPServer.class);

    private static XMPPServer instance;

    private boolean initialized = false;
    private boolean started = false;
    private NodeID nodeID;
    private static final NodeID DEFAULT_NODE_ID = NodeID.getInstance(new byte[0]);

    public static final String EXIT = "exit";

    /**
     *	服务器加载的所有模块
     */
    private Map<Class, Module> modules = new LinkedHashMap<>();

    /**
     *	侦听器，它将在服务器启动或即将停止时得到通知。
     */
    private List<XMPPServerListener> listeners = new CopyOnWriteArrayList<>();

    /**
     *	主目录的位置。所有配置文件都应该位于这里。
     */
    private File openfireHome;
    private ClassLoader loader;

    private PluginManager pluginManager;
    private InternalComponentManager componentManager;
    private RemoteSessionLocator remoteSessionLocator;

    /**
     * True if in setup mode
     */
    private boolean setupMode = true;

    private static final String STARTER_CLASSNAME =
            "org.jivesoftware.openfire.starter.ServerStarter";
    private static final String WRAPPER_CLASSNAME =
            "org.tanukisoftware.wrapper.WrapperManager";
    private boolean shuttingDown;
    private XMPPServerInfoImpl xmppServerInfo;

    /**
     *	返回XMPPServer的单例实例。
     */
    public static XMPPServer getInstance() {
        return instance;
    }

    /**
     *	创建服务器并启动它。
     */
    public XMPPServer() {
        // We may only have one instance of the server running on the JVM
        if (instance != null) {
            throw new IllegalStateException("A server is already running");
        }
        instance = this;
        start();
    }

    /**
     *	返回方法调用时当前的服务器信息。
     */
    public XMPPServerInfo getServerInfo() {
        if (!initialized) {
            throw new IllegalStateException("Not initialized yet");
        }
        return xmppServerInfo;
    }

    /**
     *	如果给定地址是服务器的本地地址(由该服务器域管理)，则返回true。
     *	即使JID的域与本地组件的服务JID匹配，也返回false。
     * @param jid the JID to check.
     * @return true if the address is a local address to this server.
     */
    public boolean isLocal( JID jid )
    {
        return jid != null && jid.getDomain().equals( xmppServerInfo.getXMPPDomain() );
    }

    /**
     *	如果给定地址与本地服务器主机名不匹配，且与组件服务JID不匹配，则返回true。
     *
     * @param jid the JID to check.
     * @return true if the given address does not match the local server hostname and does not
     *         match a component service JID.
     */
    public boolean isRemote( JID jid )
    {
        return jid != null
                && !jid.getDomain().equals( xmppServerInfo.getXMPPDomain() )
                && !componentManager.hasComponent( jid );
    }

    /**
     * Returns an ID that uniquely identifies this server in a cluster. When not running in cluster mode
     * the returned value is always the same. However, when in cluster mode the value should be set
     * when joining the cluster and must be unique even upon restarts of this node.
     *
     * @return an ID that uniquely identifies this server in a cluster.
     */
    public NodeID getNodeID() {
        return nodeID == null ? DEFAULT_NODE_ID : nodeID;
    }

    /**
     * Sets an ID that uniquely identifies this server in a cluster. When not running in cluster mode
     * the returned value is always the same. However, when in cluster mode the value should be set
     * when joining the cluster and must be unique even upon restarts of this node.
     *
     * @param nodeID an ID that uniquely identifies this server in a cluster or null if not in a cluster.
     */
    public void setNodeID(NodeID nodeID) {
        this.nodeID = nodeID;
    }

    /**
     * Returns true if the given address matches a component service JID.
     *
     * @param jid the JID to check.
     * @return true if the given address matches a component service JID.
     */
    public boolean matchesComponent( JID jid )
    {
        return jid != null
                && !jid.getDomain().equals( xmppServerInfo.getXMPPDomain() )
                && componentManager.hasComponent( jid );
    }

    /**
     * Creates an XMPPAddress local to this server.
     *
     * @param username the user name portion of the id or null to indicate none is needed.
     * @param resource the resource portion of the id or null to indicate none is needed.
     * @return an XMPPAddress for the server.
     */
    public JID createJID(String username, String resource) {
        return new JID(username, xmppServerInfo.getXMPPDomain(), resource);
    }

    /**
     * Creates an XMPPAddress local to this server. The construction of the new JID
     * can be optimized by skipping stringprep operations.
     *
     * @param username the user name portion of the id or null to indicate none is needed.
     * @param resource the resource portion of the id or null to indicate none is needed.
     * @param skipStringprep true if stringprep should not be applied.
     * @return an XMPPAddress for the server.
     */
    public JID createJID(String username, String resource, boolean skipStringprep) {
        return new JID(username, xmppServerInfo.getXMPPDomain(), resource, skipStringprep);
    }

    /**
     * Returns a collection with the JIDs of the server's admins. The collection may include
     * JIDs of local users and users of remote servers.
     *
     * @return a collection with the JIDs of the server's admins.
     */
    public Collection<JID> getAdmins() {
        return AdminManager.getInstance().getAdminAccounts();
    }

    /**
     * Adds a new server listener that will be notified when the server has been started
     * or is about to be stopped.
     *
     * @param listener the new server listener to add.
     */
    public void addServerListener(XMPPServerListener listener) {
        listeners.add(listener);
    }

    /**
     * Removes a server listener that was being notified when the server was being started
     * or was about to be stopped.
     *
     * @param listener the server listener to remove.
     */
    public void removeServerListener(XMPPServerListener listener) {
        listeners.remove(listener);
    }

    private void initialize() throws FileNotFoundException {
        locateOpenfire();

        if ("true".equals(JiveGlobals.getXMLProperty("setup"))) {
            setupMode = false;
        }

        if (isStandAlone()) {
            logger.info("Registering shutdown hook (standalone mode)");
            Runtime.getRuntime().addShutdownHook(new ShutdownHookThread());
            TaskEngine.getInstance().schedule(new Terminator(), 1000, 1000);
        }

        loader = Thread.currentThread().getContextClassLoader();

        try {
            CacheFactory.initialize();
        } catch (InitializationException e) {
            e.printStackTrace();
            logger.error(e.getMessage(), e);
        }

        JiveGlobals.migrateProperty("xmpp.domain");
        JiveGlobals.migrateProperty("xmpp.fqdn");

        JiveGlobals.migrateProperty(Log.LOG_DEBUG_ENABLED);
        Log.setDebugEnabled(JiveGlobals.getBooleanProperty(Log.LOG_DEBUG_ENABLED, false));
        
        // Update server info
        xmppServerInfo = new XMPPServerInfoImpl(new Date());

        initialized = true;

        if (setupMode && "true".equals(JiveGlobals.getXMLProperty("autosetup.run"))) {
            this.runAutoSetup();
            JiveGlobals.deleteXMLProperty("autosetup");
            JiveGlobals.deleteProperty("autosetup");
        }
    }

    void runAutoSetup() {
        // steps from setup-datasource-standard.jsp
        // do this first so that other changes persist
        if ("standard".equals(JiveGlobals.getXMLProperty("autosetup.database.mode"))) {
            JiveGlobals.setXMLProperty("database.defaultProvider.driver", JiveGlobals.getXMLProperty("autosetup.database.defaultProvider.driver"));
            JiveGlobals.setXMLProperty("database.defaultProvider.serverURL", JiveGlobals.getXMLProperty("autosetup.database.defaultProvider.serverURL"));
            JiveGlobals.setXMLProperty("database.defaultProvider.username", JiveGlobals.getXMLProperty("autosetup.database.defaultProvider.username"));
            JiveGlobals.setXMLProperty("database.defaultProvider.password", JiveGlobals.getXMLProperty("autosetup.database.defaultProvider.password"));

            int minConnections;
            int maxConnections;
            double connectionTimeout;

            try {
                minConnections = Integer.parseInt(
                    JiveGlobals.getXMLProperty("database.defaultProvider.minConnections"));
            }
            catch (Exception e) {
                minConnections = 5;
            }
            try {
                maxConnections = Integer.parseInt(
                    JiveGlobals.getXMLProperty("database.defaultProvider.maxConnections"));
            }
            catch (Exception e) {
                maxConnections = 25;
            }
            try {
                connectionTimeout = Double.parseDouble(
                    JiveGlobals.getXMLProperty("database.defaultProvider.connectionTimeout"));
            }
            catch (Exception e) {
                connectionTimeout = 1.0;
            }

            JiveGlobals.setXMLProperty("database.defaultProvider.minConnections",
                Integer.toString(minConnections));
            JiveGlobals.setXMLProperty("database.defaultProvider.maxConnections",
                Integer.toString(maxConnections));
            JiveGlobals.setXMLProperty("database.defaultProvider.connectionTimeout",
                Double.toString(connectionTimeout));
        }

        // mark setup as done, so that other things can be written to the DB
        JiveGlobals.setXMLProperty("setup","true");

        // steps from index.jsp
        String localeCode = JiveGlobals.getXMLProperty("autosetup.locale");
        logger.warn("Setting locale to" + localeCode);
        JiveGlobals.setLocale(LocaleUtils.localeCodeToLocale(localeCode.trim()));

        // steps from setup-host-settings.jsp
        JiveGlobals.setXMLProperty("xmpp.domain", JiveGlobals.getXMLProperty("autosetup.xmpp.domain"));
        JiveGlobals.setXMLProperty("xmpp.fqdn", JiveGlobals.getXMLProperty("autosetup.xmpp.fqdn"));
        JiveGlobals.migrateProperty("xmpp.domain");
        JiveGlobals.migrateProperty("xmpp.fqdn");

        JiveGlobals.setProperty("xmpp.socket.ssl.active", JiveGlobals.getXMLProperty("autosetup.xmpp.socket.ssl.active", "true"));
        JiveGlobals.setProperty("xmpp.auth.anonymous", JiveGlobals.getXMLProperty("autosetup.xmpp.auth.anonymous", "false"));

        JiveGlobals.setupPropertyEncryptionAlgorithm(JiveGlobals.getXMLProperty("autosetup.encryption.algorithm", "Blowfish")); // or AES
        JiveGlobals.setupPropertyEncryptionKey(JiveGlobals.getXMLProperty("autosetup.encryption.key", null));


        // steps from setup-profile-settings.jsp
        if ("default".equals(JiveGlobals.getXMLProperty("autosetup.authprovider.mode", "default"))) {
            JiveGlobals.setXMLProperty("connectionProvider.className",
                "org.jivesoftware.database.DefaultConnectionProvider");

            JiveGlobals.setProperty("provider.auth.className", JiveGlobals.getXMLProperty("provider.auth.className",
                org.jivesoftware.openfire.auth.DefaultAuthProvider.class.getName()));
            JiveGlobals.setProperty("provider.user.className", JiveGlobals.getXMLProperty("provider.user.className",
                org.jivesoftware.openfire.user.DefaultUserProvider.class.getName()));
            JiveGlobals.setProperty("provider.group.className", JiveGlobals.getXMLProperty("provider.group.className",
                org.jivesoftware.openfire.group.DefaultGroupProvider.class.getName()));
            JiveGlobals.setProperty("provider.vcard.className", JiveGlobals.getXMLProperty("provider.vcard.className",
                org.jivesoftware.openfire.vcard.DefaultVCardProvider.class.getName()));
            JiveGlobals.setProperty("provider.lockout.className", JiveGlobals.getXMLProperty("provider.lockout.className",
                org.jivesoftware.openfire.lockout.DefaultLockOutProvider.class.getName()));
            JiveGlobals.setProperty("provider.securityAudit.className", JiveGlobals.getXMLProperty("provider.securityAudit.className",
                org.jivesoftware.openfire.security.DefaultSecurityAuditProvider.class.getName()));
            JiveGlobals.setProperty("provider.admin.className", JiveGlobals.getXMLProperty("provider.admin.className",
                org.jivesoftware.openfire.admin.DefaultAdminProvider.class.getName()));

            // make configurable?
            JiveGlobals.setProperty("user.scramHashedPasswordOnly", "true");
        }

        // steps from setup-admin-settings.jsp
        try {
            User adminUser = UserManager.getInstance().getUser("admin");
            adminUser.setPassword(JiveGlobals.getXMLProperty("autosetup.admin.password"));
            adminUser.setEmail(JiveGlobals.getXMLProperty("autosetup.admin.email"));
            Date now = new Date();
            adminUser.setCreationDate(now);
            adminUser.setModificationDate(now);
        } catch (Exception e) {
            e.printStackTrace();
            logger.warn("There was an unexpected error encountered when "
                + "setting the new admin information. Please check your error "
                + "logs and try to remedy the problem.");
        }

        // finish setup
        this.finalSetupSteps();
        setupMode = false;
    }

    private void finalSetupSteps() {
        for (String propName : JiveGlobals.getXMLPropertyNames()) {
            if (JiveGlobals.getProperty(propName) == null) {
                JiveGlobals.setProperty(propName, JiveGlobals.getXMLProperty(propName));
            }
        }
        // Set default SASL SCRAM-SHA-1 iteration count
        JiveGlobals.setProperty("sasl.scram-sha-1.iteration-count", Integer.toString(ScramUtils.DEFAULT_ITERATION_COUNT));

        // Check if keystore (that out-of-the-box is a fallback for all keystores) already has certificates for current domain.
        CertificateStoreManager certificateStoreManager = null; // Will be a module after finishing setup.
        try {
            certificateStoreManager = new CertificateStoreManager();
            certificateStoreManager.initialize( this );
            certificateStoreManager.start();
            final IdentityStore identityStore = certificateStoreManager.getIdentityStore( ConnectionType.SOCKET_C2S );
            identityStore.ensureDomainCertificates( "DSA", "RSA" );

        } catch (Exception e) {
            logger.error("Error generating self-signed certificates", e);
        } finally {
            if (certificateStoreManager != null)
            {
                certificateStoreManager.stop();
                certificateStoreManager.destroy();
            }
        }

        // Initialize list of admins now (before we restart Jetty)
        AdminManager.getInstance().getAdminAccounts();
    }

    /**
     * Finish the setup process. Because this method is meant to be called from inside
     * the Admin console plugin, it spawns its own thread to do the work so that the
     * class loader is correct.
     */
    public void finishSetup() {
        if (!setupMode) {
            return;
        }

        this.finalSetupSteps();

        // Make sure that setup finished correctly.
        if ("true".equals(JiveGlobals.getXMLProperty("setup"))) {
            // Iterate through all the provided XML properties and set the ones that haven't
            // already been touched by setup prior to this method being called.

            Thread finishSetup = new Thread() {
                @Override
                public void run() {
                    try {
                        if (isStandAlone()) {
                            // Always restart the HTTP server manager. This covers the case
                            // of changing the ports, as well as generating self-signed certificates.
                        
                            // Wait a short period before shutting down the admin console.
                            // Otherwise, the page that requested the setup finish won't
                            // render properly!
                            Thread.sleep(1000);
                            ((AdminConsolePlugin) pluginManager.getPlugin("admin")).restart();
//                            ((AdminConsolePlugin) pluginManager.getPlugin("admin")).shutdown();
//                            ((AdminConsolePlugin) pluginManager.getPlugin("admin")).startup();
                        }

                        verifyDataSource();
                        // First load all the modules so that modules may access other modules while
                        // being initialized
                        loadModules();
                        // Initize all the modules
                        initModules();
                        // Start all the modules
                        startModules();
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                        logger.error(e.getMessage(), e);
                        shutdownServer();
                    }
                }
            };
            // Use the correct class loader.
            finishSetup.setContextClassLoader(loader);
            finishSetup.start();
            // We can now safely indicate that setup has finished
            setupMode = false;
        }
    }

    public void start() {
        try {
        	//初始化
            initialize();

            // Create PluginManager now (but don't start it) so that modules may use it
            // 创建PluginManager(但不启动它)以便模块可以使用它
            File pluginDir = new File(openfireHome, "plugins");
            pluginManager = new PluginManager(pluginDir);

            // If the server has already been setup then we can start all the server's modules
            // 如果服务器已经设置好，那么我们就可以启动所有服务器的模块
            if (!setupMode) {
                verifyDataSource();
                // 首先加载所有模块，以便模块在初始化时可以访问其他模块
                loadModules();
                // 初始化所有模块
                initModules();
                // 启动所有模块
                startModules();
            }
            // 初始化数据
            ServerTrafficCounter.initStatistics();

            // 加载插件(在安装模式下只加载管理控制台)
            pluginManager.start();

            // 日志记录服务器已启动
            String startupBanner = LocaleUtils.getLocalizedString("short.title") + " " + xmppServerInfo.getVersion().getVersionString() +
                    " [" + JiveGlobals.formatDateTime(new Date()) + "]";
            logger.info(startupBanner);
            System.out.println(startupBanner);

            started = true;
            
            // 通知服务器侦听器(XMPPServerListener)服务器已经启动
            for (XMPPServerListener listener : listeners) {
                listener.serverStarted();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getMessage(), e);
            System.out.println(LocaleUtils.getLocalizedString("startup.error"));
            shutdownServer();
        }
    }

    private void loadModules() {
        // Load boot modules
        loadModule(RoutingTableImpl.class.getName());
        loadModule(AuditManagerImpl.class.getName());
        loadModule(RosterManager.class.getName());
        loadModule(PrivateStorage.class.getName());
        // Load core modules
        loadModule(PresenceManagerImpl.class.getName());
        loadModule(SessionManager.class.getName());
        loadModule(PacketRouterImpl.class.getName());
        loadModule(IQRouter.class.getName());
        loadModule(MessageRouter.class.getName());
        loadModule(PresenceRouter.class.getName());
        loadModule(MulticastRouter.class.getName());
        loadModule(PacketTransporterImpl.class.getName());
        loadModule(PacketDelivererImpl.class.getName());
        loadModule(TransportHandler.class.getName());
        loadModule(OfflineMessageStrategy.class.getName());
        loadModule(OfflineMessageStore.class.getName());
        loadModule(VCardManager.class.getName());
        // Load standard modules
        loadModule(IQBindHandler.class.getName());
        loadModule(IQSessionEstablishmentHandler.class.getName());
        loadModule(IQPingHandler.class.getName());
        loadModule(IQPrivateHandler.class.getName());
        loadModule(IQRegisterHandler.class.getName());
        loadModule(IQRosterHandler.class.getName());
        loadModule(IQEntityTimeHandler.class.getName());
        loadModule(IQvCardHandler.class.getName());
        loadModule(IQVersionHandler.class.getName());
        loadModule(IQLastActivityHandler.class.getName());
        loadModule(PresenceSubscribeHandler.class.getName());
        loadModule(PresenceUpdateHandler.class.getName());
        loadModule(IQOfflineMessagesHandler.class.getName());
        loadModule(IQPEPHandler.class.getName());
        loadModule(IQPEPOwnerHandler.class.getName());
        loadModule(MulticastDNSService.class.getName());
        loadModule(IQSharedGroupHandler.class.getName());
        loadModule(AdHocCommandHandler.class.getName());
        loadModule(IQPrivacyHandler.class.getName());
        loadModule(DefaultFileTransferManager.class.getName());
        loadModule(FileTransferProxy.class.getName());
        loadModule(MediaProxyService.class.getName());
        loadModule(PubSubModule.class.getName());
        loadModule(IQDiscoInfoHandler.class.getName());
        loadModule(IQDiscoItemsHandler.class.getName());
        loadModule(UpdateManager.class.getName());
        loadModule(FlashCrossDomainHandler.class.getName());
        loadModule(InternalComponentManager.class.getName());
        loadModule(MultiUserChatManager.class.getName());
        loadModule(IQMessageCarbonsHandler.class.getName());
        loadModule(CertificateStoreManager.class.getName());

        // Load this module always last since we don't want to start listening for clients
        // before the rest of the modules have been started
        loadModule(ConnectionManagerImpl.class.getName());
        // Keep a reference to the internal component manager
        componentManager = getComponentManager();
    }

    /**
     *	加载模块
     *
     * @param module the name of the class that implements the Module interface.
     */
    private void loadModule(String module) {
        try {
            Class<Module> modClass = (Class<Module>) loader.loadClass(module);
            Module mod = modClass.newInstance();
            this.modules.put(modClass, mod);
        }
        catch (Exception e) {
            e.printStackTrace();
            logger.error(LocaleUtils.getLocalizedString("admin.error"), e);
        }
    }

    /**
     * 
     * @description 初始化模块
     * @return void
     * @throws
     */
    private void initModules() {
        for (Module module : modules.values()) {
            try {
                module.initialize(this);
            }
            catch (Exception e) {
                e.printStackTrace();
                // Remove the failed initialized module
                this.modules.remove(module.getClass());
                module.stop();
                module.destroy();
                logger.error(LocaleUtils.getLocalizedString("admin.error"), e);
            }
        }
    }

    /**
     * <p>在加载和初始化所有模块之后，调用此方法遍历已知模块并启动它们。</p>
     */
    private void startModules() {
        for (Module module : modules.values()) {
            try {
                logger.debug( "Starting module: " + module.getName() );
                module.start();
            }
            catch (Exception e) {
                logger.error( "An exception occurred while starting module '{}'.", module.getName(), e );
            }
        }
    }

    /**
     *	仅当服务器可重新启动时，才重新启动服务器及其所有模块。否则什么都不做。
     */
    public void restart() {
        if (isStandAlone() && isRestartable()) {
            try {
                Class<?> wrapperClass = Class.forName(WRAPPER_CLASSNAME);
                Method restartMethod = wrapperClass.getMethod("restart", (Class []) null);
                restartMethod.invoke(null, (Object []) null);
            }
            catch (Exception e) {
                logger.error("Could not restart container", e);
            }
        }
    }

    /**
     *	只有在独立模式下运行时才重新启动HTTP服务器。
     *	重新启动过程将在另一个线程中完成，该线程将等待1秒，然后再执行实际的重新启动。
     *	延迟将给请求重新启动的页面提供时间，以完全呈现其内容。
     */
    public void restartHTTPServer() {
        Thread restartThread = new Thread() {
            @Override
            public void run() {
                if (isStandAlone()) {
                    // Restart the HTTP server manager. This covers the case
                    // of changing the ports, as well as generating self-signed certificates.

                    // Wait a short period before shutting down the admin console.
                    // Otherwise, this page won't render properly!
                    try {
                        Thread.sleep(1000);
                        ((AdminConsolePlugin) pluginManager.getPlugin("admin")).shutdown();
                        ((AdminConsolePlugin) pluginManager.getPlugin("admin")).startup();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        restartThread.setContextClassLoader(loader);
        restartThread.start();
    }

    /**
     * Stops the server only if running in standalone mode. Do nothing if the server is running
     * inside of another server.
     */
    public void stop() {
        logger.info("Initiating shutdown ...");
        // Only do a system exit if we're running standalone
        if (isStandAlone()) {
            // if we're in a wrapper, we have to tell the wrapper to shut us down
            if (isRestartable()) {
                try {
                    Class<?> wrapperClass = Class.forName(WRAPPER_CLASSNAME);
                    Method stopMethod = wrapperClass.getMethod("stop", Integer.TYPE);
                    stopMethod.invoke(null, 0);
                }
                catch (Exception e) {
                    logger.error("Could not stop container", e);
                }
            }
            else {
                shutdownServer();
                Thread shutdownThread = new ShutdownThread();
                shutdownThread.setDaemon(true);
                shutdownThread.start();
            }
        }
        else {
            // Close listening socket no matter what the condition is in order to be able
            // to be restartable inside a container.
            shutdownServer();
        }
    }

    public boolean isSetupMode() {
        return setupMode;
    }

    public boolean isRestartable() {
        boolean restartable;
        try {
            restartable = Class.forName(WRAPPER_CLASSNAME) != null;
        }
        catch (ClassNotFoundException e) {
            restartable = false;
        }
        return restartable;
    }

    /**
     * Returns if the server is running in standalone mode. We consider that it's running in
     * standalone if the "org.jivesoftware.openfire.starter.ServerStarter" class is present in the
     * system.
     *
     * @return true if the server is running in standalone mode.
     */
    public boolean isStandAlone() {
        boolean standalone;
        try {
            standalone = Class.forName(STARTER_CLASSNAME) != null;
        }
        catch (ClassNotFoundException e) {
            standalone = false;
        }
        return standalone;
    }

    /**
     * 验证数据库是否可访问。
     */
    private void verifyDataSource() {
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement("SELECT count(*) FROM ofID");
            rs = pstmt.executeQuery();
            rs.next();
        }
        catch (Exception e) {
            System.err.println("Database setup or configuration error: " +
                    "Please verify your database settings and check the " +
                    "logs/error.log file for detailed error messages.");
            logger.error("Database could not be accessed", e);
            throw new IllegalArgumentException(e);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
    }

    /**
     * Verifies that the given home guess is a real Openfire home directory.
     * We do the verification by checking for the Openfire config file in
     * the config dir of jiveHome.
     *
     * @param homeGuess a guess at the path to the home directory.
     * @param jiveConfigName the name of the config file to check.
     * @return a file pointing to the home directory or null if the
     *         home directory guess was wrong.
     * @throws java.io.FileNotFoundException if there was a problem with the home
     *                                       directory provided
     */
    private File verifyHome(String homeGuess, String jiveConfigName) throws FileNotFoundException {
        File openfireHome = new File(homeGuess);
        File configFile = new File(openfireHome, jiveConfigName);
        if (!configFile.exists()) {
            throw new FileNotFoundException();
        }
        else {
            try {
                return new File(openfireHome.getCanonicalPath());
            }
            catch (Exception ex) {
                throw new FileNotFoundException();
            }
        }
    }

    /**
     * <p>为容器检索jive home</p>
     *
     * @throws FileNotFoundException If jiveHome could not be located
     */
    private void locateOpenfire() throws FileNotFoundException {
        String jiveConfigName = "conf" + File.separator + "openfire.xml";
        // First, try to load it openfireHome as a system property.
        if (openfireHome == null) {
            String homeProperty = System.getProperty("openfireHome");
            try {
                if (homeProperty != null) {
                    openfireHome = verifyHome(homeProperty, jiveConfigName);
                }
            }
            catch (FileNotFoundException fe) {
                // Ignore.
            }
        }

        // If we still don't have home, let's assume this is standalone
        // and just look for home in a standard sub-dir location and verify
        // by looking for the config file
        // 如果仍然没有home，可假设是独立的，只需要在标准的子目录位置中查找home，并通过查找配置文件来验证。
        if (openfireHome == null) {
            try {
                openfireHome = verifyHome("..", jiveConfigName).getCanonicalFile();
            } catch (IOException ie) {
                // Ignore.
            }
        }

        // If home is still null, no outside process has set it and
        // we have to attempt to load the value from openfire_init.xml,
        // which must be in the classpath.
        // 如果home仍然为空，没有外部进程设置它，我们必须尝试从openfire_init.xml加载值,该文件必须在类路径中。
        if (openfireHome == null) {
            try (InputStream in = getClass().getResourceAsStream("/openfire_init.xml")) {
                if (in != null) {
                    SAXReader reader = new SAXReader();
                    Document doc = reader.read(in);
                    String path = doc.getRootElement().getText();
                    try {
                        if (path != null) {
                            openfireHome = verifyHome(path, jiveConfigName);
                        }
                    }
                    catch (FileNotFoundException fe) {
                        fe.printStackTrace();
                    }
                }
            }
            catch (Exception e) {
                System.err.println("Error loading openfire_init.xml to find home.");
                e.printStackTrace();
            }
        }

        if (openfireHome == null) {
            System.err.println("Could not locate home");
            throw new FileNotFoundException();
        }
        else {
            // Set the home directory for the config file
            JiveGlobals.setHomeDirectory(openfireHome.toString());
            // Set the name of the config file
            JiveGlobals.setConfigName(jiveConfigName);
        }
    }

    /**
     * This timer task is used to monitor the System input stream
     * for a "terminate" command from the launcher (or the console). 
     * This allows for a graceful shutdown when Openfire is started 
     * via the launcher, especially in Windows.
     */
    private class Terminator extends TimerTask {
        private BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        @Override
        public void run() {
            try { 
                if (stdin.ready()) {
                    if (EXIT.equalsIgnoreCase(stdin.readLine())) {
                        System.exit(0); // invokes shutdown hook(s)
                    }
                }
            } catch (IOException ioe) {
                logger.error("Error reading console input", ioe);
            }
        }
    }
    
    /**
     * <p>A thread to ensure the server shuts down no matter what.</p>
     * <p>Spawned when stop() is called in standalone mode, we wait a few
     * seconds then call system exit().</p>
     *
     * @author Iain Shigeoka
     */
    private class ShutdownHookThread extends Thread {

        /**
         * <p>Logs the server shutdown.</p>
         */
        @Override
        public void run() {
            shutdownServer();
            logger.info("Server halted");
            System.err.println("Server halted");
        }
    }

    /**
     * <p>A thread to ensure the server shuts down no matter what.</p>
     * <p>Spawned when stop() is called in standalone mode, we wait a few
     * seconds then call system exit().</p>
     *
     * @author Iain Shigeoka
     */
    private class ShutdownThread extends Thread {

        /**
         * <p>Shuts down the JVM after a 5 second delay.</p>
         */
        @Override
        public void run() {
            try {
                Thread.sleep(5000);
                // No matter what, we make sure it's dead
                System.exit(0);
            }
            catch (InterruptedException e) {
                // Ignore.
            }

        }
    }

    /**
     * Makes a best effort attempt to shutdown the server
     */
    private void shutdownServer() {
        shuttingDown = true;
        ClusterManager.shutdown();
        // Notify server listeners that the server is about to be stopped
        for (XMPPServerListener listener : listeners) {
            try {
                listener.serverStopping();
            } catch (Exception ex) {
                logger.error("Exception during listener shutdown", ex);
            }
        }
        // If we don't have modules then the server has already been shutdown
        if (modules.isEmpty()) {
            return;
        }
        logger.info("Shutting down " + modules.size() + " modules ...");
        // Get all modules and stop and destroy them
        for (Module module : modules.values()) {
            try {
                module.stop();
                module.destroy();
            } catch (Exception ex) {
                logger.error("Exception during module shutdown", ex);
            }
        }
        // Stop all plugins
        logger.info("Shutting down plugins ...");
        if (pluginManager != null) {
            try {
                pluginManager.shutdown();
            } catch (Exception ex) {
                logger.error("Exception during plugin shutdown", ex);
            }
        }
        modules.clear();
        // Stop the Db connection manager.
        try {	
            DbConnectionManager.destroyConnectionProvider();
        } catch (Exception ex) {
            logger.error("Exception during DB shutdown", ex);
        }

        // Shutdown the task engine.
        TaskEngine.getInstance().shutdown();

        // hack to allow safe stopping
        logger.info("Openfire stopped");
    }
    
    /**
     * Returns true if the server is being shutdown.
     *
     * @return true if the server is being shutdown.
     */
    public boolean isShuttingDown() {
        return shuttingDown;
    }

    /**
     * Returns the <code>ConnectionManager</code> registered with this server. The
     * <code>ConnectionManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>ConnectionManager</code> registered with this server.
     */
    public ConnectionManager getConnectionManager() {
        return (ConnectionManager) modules.get(ConnectionManagerImpl.class);
    }

    /**
     * Returns the <code>RoutingTable</code> registered with this server. The
     * <code>RoutingTable</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>RoutingTable</code> registered with this server.
     */
    public RoutingTable getRoutingTable() {
        return (RoutingTable) modules.get(RoutingTableImpl.class);
    }

    /**
     * Returns the <code>PacketDeliverer</code> registered with this server. The
     * <code>PacketDeliverer</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PacketDeliverer</code> registered with this server.
     */
    public PacketDeliverer getPacketDeliverer() {
        return (PacketDeliverer) modules.get(PacketDelivererImpl.class);
    }

    /**
     * Returns the <code>RosterManager</code> registered with this server. The
     * <code>RosterManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>RosterManager</code> registered with this server.
     */
    public RosterManager getRosterManager() {
        return (RosterManager) modules.get(RosterManager.class);
    }

    /**
     * Returns the <code>PresenceManager</code> registered with this server. The
     * <code>PresenceManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PresenceManager</code> registered with this server.
     */
    public PresenceManager getPresenceManager() {
        return (PresenceManager) modules.get(PresenceManagerImpl.class);
    }

    /**
     * Returns the <code>OfflineMessageStore</code> registered with this server. The
     * <code>OfflineMessageStore</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>OfflineMessageStore</code> registered with this server.
     */
    public OfflineMessageStore getOfflineMessageStore() {
        return (OfflineMessageStore) modules.get(OfflineMessageStore.class);
    }

    /**
     * Returns the <code>OfflineMessageStrategy</code> registered with this server. The
     * <code>OfflineMessageStrategy</code> was registered with the server as a module while starting
     * up the server.
     *
     * @return the <code>OfflineMessageStrategy</code> registered with this server.
     */
    public OfflineMessageStrategy getOfflineMessageStrategy() {
        return (OfflineMessageStrategy) modules.get(OfflineMessageStrategy.class);
    }

    /**
     * Returns the <code>PacketRouter</code> registered with this server. The
     * <code>PacketRouter</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PacketRouter</code> registered with this server.
     */
    public PacketRouter getPacketRouter() {
        return (PacketRouter) modules.get(PacketRouterImpl.class);
    }

    /**
     * Returns the <code>IQRegisterHandler</code> registered with this server. The
     * <code>IQRegisterHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>IQRegisterHandler</code> registered with this server.
     */
    public IQRegisterHandler getIQRegisterHandler() {
        return (IQRegisterHandler) modules.get(IQRegisterHandler.class);
    }

    /**
     * Returns the <code>IQPEPHandler</code> registered with this server. The
     * <code>IQPEPHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>IQPEPHandler</code> registered with this server.
     */
    public IQPEPHandler getIQPEPHandler() {
        return (IQPEPHandler) modules.get(IQPEPHandler.class);
    }

    /**
     * Returns the <code>PluginManager</code> instance registered with this server.
     *
     * @return the PluginManager instance.
     */
    public PluginManager getPluginManager() {
        return pluginManager;
    }

    /**
     * Returns the <code>PubSubModule</code> registered with this server. The
     * <code>PubSubModule</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PubSubModule</code> registered with this server.
     */
    public PubSubModule getPubSubModule() {
        return (PubSubModule) modules.get(PubSubModule.class);
    }

    /**
     * Returns a list with all the modules registered with the server that inherit from IQHandler.
     *
     * @return a list with all the modules registered with the server that inherit from IQHandler.
     */
    public List<IQHandler> getIQHandlers() {
        List<IQHandler> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof IQHandler) {
                answer.add((IQHandler) module);
            }
        }
        return answer;
    }

    /**
     * Returns the <code>SessionManager</code> registered with this server. The
     * <code>SessionManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>SessionManager</code> registered with this server.
     */
    public SessionManager getSessionManager() {
        return (SessionManager) modules.get(SessionManager.class);
    }

    /**
     * Returns the <code>TransportHandler</code> registered with this server. The
     * <code>TransportHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>TransportHandler</code> registered with this server.
     */
    public TransportHandler getTransportHandler() {
        return (TransportHandler) modules.get(TransportHandler.class);
    }

    /**
     * Returns the <code>PresenceUpdateHandler</code> registered with this server. The
     * <code>PresenceUpdateHandler</code> was registered with the server as a module while starting
     * up the server.
     *
     * @return the <code>PresenceUpdateHandler</code> registered with this server.
     */
    public PresenceUpdateHandler getPresenceUpdateHandler() {
        return (PresenceUpdateHandler) modules.get(PresenceUpdateHandler.class);
    }

    /**
     * Returns the <code>PresenceSubscribeHandler</code> registered with this server. The
     * <code>PresenceSubscribeHandler</code> was registered with the server as a module while
     * starting up the server.
     *
     * @return the <code>PresenceSubscribeHandler</code> registered with this server.
     */
    public PresenceSubscribeHandler getPresenceSubscribeHandler() {
        return (PresenceSubscribeHandler) modules.get(PresenceSubscribeHandler.class);
    }

    /**
     * Returns the <code>IQRouter</code> registered with this server. The
     * <code>IQRouter</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>IQRouter</code> registered with this server.
     */
    public IQRouter getIQRouter() {
        return (IQRouter) modules.get(IQRouter.class);
    }

    /**
     * Returns the <code>MessageRouter</code> registered with this server. The
     * <code>MessageRouter</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>MessageRouter</code> registered with this server.
     */
    public MessageRouter getMessageRouter() {
        return (MessageRouter) modules.get(MessageRouter.class);
    }

    /**
     * Returns the <code>PresenceRouter</code> registered with this server. The
     * <code>PresenceRouter</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PresenceRouter</code> registered with this server.
     */
    public PresenceRouter getPresenceRouter() {
        return (PresenceRouter) modules.get(PresenceRouter.class);
    }

    /**
     * Returns the <code>MulticastRouter</code> registered with this server. The
     * <code>MulticastRouter</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>MulticastRouter</code> registered with this server.
     */
    public MulticastRouter getMulticastRouter() {
        return (MulticastRouter) modules.get(MulticastRouter.class);
    }

    /**
     * Returns the <code>UserManager</code> registered with this server. The
     * <code>UserManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>UserManager</code> registered with this server.
     */
    public UserManager getUserManager() {
        return UserManager.getInstance();
    }

    /**
     * Returns the <code>LockOutManager</code> registered with this server.  The
     * <code>LockOutManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>LockOutManager</code> registered with this server.
     */
    public LockOutManager getLockOutManager() {
        return LockOutManager.getInstance();
    }

    /**
     * Returns the <code>UpdateManager</code> registered with this server. The
     * <code>UpdateManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>UpdateManager</code> registered with this server.
     */
    public UpdateManager getUpdateManager() {
        return (UpdateManager) modules.get(UpdateManager.class);
    }

    /**
     * Returns the <code>AuditManager</code> registered with this server. The
     * <code>AuditManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>AuditManager</code> registered with this server.
     */
    public AuditManager getAuditManager() {
        return (AuditManager) modules.get(AuditManagerImpl.class);
    }

    /**
     * Returns a list with all the modules that provide "discoverable" features.
     *
     * @return a list with all the modules that provide "discoverable" features.
     */
    public List<ServerFeaturesProvider> getServerFeaturesProviders() {
        List<ServerFeaturesProvider> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof ServerFeaturesProvider) {
                answer.add((ServerFeaturesProvider) module);
            }
        }
        return answer;
    }
 
    /**
     * Returns a list with all the modules that provide "discoverable" identities.
     *
     * @return a list with all the modules that provide "discoverable" identities.
     */
    public List<ServerIdentitiesProvider> getServerIdentitiesProviders() {
        List<ServerIdentitiesProvider> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof ServerIdentitiesProvider) {
                answer.add((ServerIdentitiesProvider) module);
            }
        }
        return answer;
    }

    /**
     * Returns a list with all the modules that provide "discoverable" items associated with
     * the server.
     *
     * @return a list with all the modules that provide "discoverable" items associated with
     *         the server.
     */
    public List<ServerItemsProvider> getServerItemsProviders() {
        List<ServerItemsProvider> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof ServerItemsProvider) {
                answer.add((ServerItemsProvider) module);
            }
        }
        return answer;
    }
    
    /**
     * Returns a list with all the modules that provide "discoverable" user identities.
     *
     * @return a list with all the modules that provide "discoverable" user identities.
     */
    public List<UserIdentitiesProvider> getUserIdentitiesProviders() {
        List<UserIdentitiesProvider> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof UserIdentitiesProvider) {
                answer.add((UserIdentitiesProvider) module);
            }
        }
        return answer;
    }

    /**
     * Returns a list with all the modules that provide "discoverable" items associated with
     * users.
     *
     * @return a list with all the modules that provide "discoverable" items associated with
     *         users.
     */
    public List<UserItemsProvider> getUserItemsProviders() {
        List<UserItemsProvider> answer = new ArrayList<>();
        for (Module module : modules.values()) {
            if (module instanceof UserItemsProvider) {
                answer.add((UserItemsProvider) module);
            }
        }
        return answer;
    }

    /**
     * Returns the <code>IQDiscoInfoHandler</code> registered with this server. The
     * <code>IQDiscoInfoHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>IQDiscoInfoHandler</code> registered with this server.
     */
    public IQDiscoInfoHandler getIQDiscoInfoHandler() {
        return (IQDiscoInfoHandler) modules.get(IQDiscoInfoHandler.class);
    }

    /**
     * Returns the <code>IQDiscoItemsHandler</code> registered with this server. The
     * <code>IQDiscoItemsHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>IQDiscoItemsHandler</code> registered with this server.
     */
    public IQDiscoItemsHandler getIQDiscoItemsHandler() {
        return (IQDiscoItemsHandler) modules.get(IQDiscoItemsHandler.class);
    }

    /**
     * Returns the <code>PrivateStorage</code> registered with this server. The
     * <code>PrivateStorage</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>PrivateStorage</code> registered with this server.
     */
    public PrivateStorage getPrivateStorage() {
        return (PrivateStorage) modules.get(PrivateStorage.class);
    }

    /**
     * Returns the <code>MultiUserChatManager</code> registered with this server. The
     * <code>MultiUserChatManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>MultiUserChatManager</code> registered with this server.
     */
    public MultiUserChatManager getMultiUserChatManager() {
        return (MultiUserChatManager) modules.get(MultiUserChatManager.class);
    }

    /**
     * Returns the <code>AdHocCommandHandler</code> registered with this server. The
     * <code>AdHocCommandHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>AdHocCommandHandler</code> registered with this server.
     */
    public AdHocCommandHandler getAdHocCommandHandler() {
        return (AdHocCommandHandler) modules.get(AdHocCommandHandler.class);
    }

    /**
     * Returns the <code>FileTransferProxy</code> registered with this server. The
     * <code>FileTransferProxy</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>FileTransferProxy</code> registered with this server.
     */
    public FileTransferProxy getFileTransferProxy() {
        return (FileTransferProxy) modules.get(FileTransferProxy.class);
    }

    /**
     * Returns the <code>FileTransferManager</code> registered with this server. The
     * <code>FileTransferManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>FileTransferProxy</code> registered with this server.
     */
    public FileTransferManager getFileTransferManager() {
        return (FileTransferManager) modules.get(DefaultFileTransferManager.class);
    }

    /**
     * Returns the <code>MediaProxyService</code> registered with this server. The
     * <code>MediaProxyService</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>MediaProxyService</code> registered with this server.
     */
    public MediaProxyService getMediaProxyService() {
        return (MediaProxyService) modules.get(MediaProxyService.class);
    }

    /**
     * Returns the <code>FlashCrossDomainHandler</code> registered with this server. The
     * <code>FlashCrossDomainHandler</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>FlashCrossDomainHandler</code> registered with this server.
     */
    public FlashCrossDomainHandler getFlashCrossDomainHandler() {
        return (FlashCrossDomainHandler) modules.get(FlashCrossDomainHandler.class);
    }

    /**
     * Returns the <code>VCardManager</code> registered with this server. The
     * <code>VCardManager</code> was registered with the server as a module while starting up
     * the server.
     * @return the <code>VCardManager</code> registered with this server.
     */
    public VCardManager getVCardManager() {
        return VCardManager.getInstance();
    }

    /**
     * Returns the <code>InternalComponentManager</code> registered with this server. The
     * <code>InternalComponentManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>InternalComponentManager</code> registered with this server.
     */
    private InternalComponentManager getComponentManager() {
        return (InternalComponentManager) modules.get(InternalComponentManager.class);
    }

    /**
     * Returns the <code>CertificateStoreManager</code> registered with this server. The
     * <code>CertificateStoreManager</code> was registered with the server as a module while starting up
     * the server.
     *
     * @return the <code>CertificateStoreManager</code> registered with this server.
     */
    public CertificateStoreManager getCertificateStoreManager() {
        return (CertificateStoreManager) modules.get( CertificateStoreManager.class );
    }
    /**
     * Returns the locator to use to find sessions hosted in other cluster nodes. When not running
     * in a cluster a <tt>null</tt> value is returned.
     *
     * @return the locator to use to find sessions hosted in other cluster nodes.
     */
    public RemoteSessionLocator getRemoteSessionLocator() {
        return remoteSessionLocator;
    }

    /**
     * Sets the locator to use to find sessions hosted in other cluster nodes. When not running
     * in a cluster set a <tt>null</tt> value.
     *
     * @param remoteSessionLocator the locator to use to find sessions hosted in other cluster nodes.
     */
    public void setRemoteSessionLocator(RemoteSessionLocator remoteSessionLocator) {
        this.remoteSessionLocator = remoteSessionLocator;
    }

    /**
     * Returns whether or not the server has been started.
     * 
     * @return whether or not the server has been started.
     */
    public boolean isStarted() {
        return started;
    }
}
