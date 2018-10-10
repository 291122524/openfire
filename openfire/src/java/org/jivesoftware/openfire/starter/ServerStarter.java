/*
 *
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

package org.jivesoftware.openfire.starter;

import org.jivesoftware.util.Log;

import java.io.File;
/**
 * XMPP核心服务启动引导类, 配置类加载器, 确保服务启动简单、动态。
 *
 * 这个类只适用于独立模式。 Openfire服务器通过J2EE容器(servlet/EJB)启动将使用这些环境中的类加载工具，以确保适当的启动。
 * <p>
 *
 * Tasks:<ul>
 *      <li>解压lib目录中的所有包文件(Pack200编码JAR文件)。</li>
 *      <li>将lib目录中的所有jar添加到类路径中。</li>
 *      <li>将config目录添加到loadResource()的类路径中</li>
 *      <li>启动服务</li>
 * </ul>
 *
 * Note: if the enviroment property <tt>openfire.lib.dir</tt> is specified
 * ServerStarter将尝试使用这个值作为 openfire's lib 目录。
 * 如果property 没有指定, 将使用默认值 ../lib .
 *
 * @author Iain Shigeoka
 */
public class ServerStarter {

    /**
     * Default to this location if one has not been specified
     */
    private static final String DEFAULT_LIB_DIR = "../lib";
    private static final String DEFAULT_ADMIN_LIB_DIR = "../plugins/admin/webapp/WEB-INF/lib";

    public static void main(String [] args) {
        new ServerStarter().start();
    }

    /**
     * Starts the server by loading and instantiating the bootstrap
     * container. Once the start method is called, the server is
     * started and the server starter should not be used again.
     */
    private void start() {
        // Setup the classpath using JiveClassLoader
        try {
            // Load up the bootstrap container
        	// 加载引导容器
            final ClassLoader parent = findParentClassLoader();

            String libDirString = System.getProperty("openfire.lib.dir");

            File libDir;
            if (libDirString != null) {
                // If the lib directory property has been specified and it actually
                // exists use it, else use the default
                libDir = new File(libDirString);
                if (!libDir.exists()) {
                    Log.warn("Lib directory " + libDirString +
                            " does not exist. Using default " + DEFAULT_LIB_DIR);
                    libDir = new File(DEFAULT_LIB_DIR);
                }
            }
            else {
                libDir = new File(DEFAULT_LIB_DIR);
            }

            String adminLibDirString = System.getProperty("openfireHome");
            if (adminLibDirString == null) {
                adminLibDirString = DEFAULT_ADMIN_LIB_DIR;
            }
            else {
                adminLibDirString = adminLibDirString+"/plugins/admin/webapp/WEB-INF/lib";
            }
            File adminLibDir = new File(adminLibDirString);
            if (!adminLibDir.exists()) {
                Log.warn("Admin Lib Directory " + adminLibDirString +
                    " does not exist. Web admin console may not work.");
            }

            ClassLoader loader = new JiveClassLoader(parent, libDir);

            Thread.currentThread().setContextClassLoader(loader);
            Class containerClass = loader.loadClass(
                    "org.jivesoftware.openfire.XMPPServer");
            containerClass.newInstance();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Locates the best class loader based on context (see class description).
     *
     * @return The best parent classloader to use
     */
    private ClassLoader findParentClassLoader() {
        ClassLoader parent = Thread.currentThread().getContextClassLoader();
        if (parent == null) {
            parent = this.getClass().getClassLoader();
            if (parent == null) {
                parent = ClassLoader.getSystemClassLoader();
            }
        }
        return parent;
    }
}
