//
//  ========================================================================
//  Copyright (c) 1995-2014 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.alpn;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * {@link ALPN} provides an API to applications that want to make use of the
 * <a href="http://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg">Application Layer Protocol Negotiation</a>.
 * <p/>
 * The ALPN extension is only available when using the TLS protocol, therefore applications must
 * ensure that the TLS protocol is used:
 * <pre>
 * SSLContext context = SSLContext.getInstance("TLSv1");
 * </pre>
 * Refer to the
 * <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SSLContext">list
 * of standard SSLContext protocol names</a> for further information on TLS protocol versions supported.
 * <p/>
 * Applications must register instances of either {@link SSLSocket} or {@link SSLEngine} with a
 * {@link ClientProvider} or with a {@link ServerProvider}, depending whether they are on client or
 * server side.
 * <p/>
 * The ALPN implementation will invoke the provider callbacks to allow applications to interact
 * with the negotiation of the protocol.
 * <p/>
 * Client side typical usage:
 * <pre>
 * SSLSocket sslSocket = ...;
 * ALPN.put(sslSocket, new ALPN.ClientProvider()
 * {
 *     &#64;Override
 *     public boolean supports()
 *     {
 *         return true;
 *     }
 *
 *     &#64;Override
 *     public List&lt;String&gt; protocols()
 *     {
 *         return Arrays.asList("spdy/3", "http/1.1");
 *     }
 *
 *     &#64;Override
 *     public void unsupported()
 *     {
 *     }
 *
 *     &#64;Override
 *     public void selected(String protocol)
 *     {
 *         System.out.println("Selected protocol: " + protocol);
 *     }
 *  });
 * </pre>
 * Server side typical usage:
 * <pre>
 * SSLSocket sslSocket = ...;
 * ALPN.put(sslSocket, new ALPN.ServerProvider()
 * {
 *     &#64;Override
 *     public void unsupported()
 *     {
 *     }
 *
 *     &#64;Override
 *     public String select(List&lt;String&gt; protocols)
 *     {
 *         return protocols.get(0);
 *     }
 *  });
 * </pre>
 * Applications must ensure to deregister {@link SSLSocket} or {@link SSLEngine} instances,
 * because they are kept in a global map.
 * Deregistration should typically happen when the application detects the end of the protocol
 * negotiation, and/or when the associated socket connection is closed.
 * <p/>
 * In order to help application development, you can set the {@link ALPN#debug} field
 * to {@code true} to have debug code printed to {@link System#err}.
 */
public class ALPN
{
    /**
     * Flag that enables printing of debug statements to {@link System#err}.
     */
    public static boolean debug = false;

    private static Map<Object, Provider> objects = Collections.synchronizedMap(new HashMap<Object, Provider>());

    private ALPN()
    {
    }

    /**
     * Registers a SSLSocket with a provider.
     *
     * @param socket   the socket to register with the provider
     * @param provider the provider to register with the socket
     * @see #remove(SSLSocket)
     */
    public static void put(SSLSocket socket, Provider provider)
    {
        objects.put(socket, provider);
    }

    /**
     * @param socket a socket registered with {@link #put(SSLSocket, Provider)}
     * @return the provider registered with the given socket
     */
    public static Provider get(SSLSocket socket)
    {
        return objects.get(socket);
    }

    /**
     * Unregisters the given SSLSocket.
     *
     * @param socket the socket to unregister
     * @return the provider registered with the socket
     * @see #put(SSLSocket, Provider)
     */
    public static Provider remove(SSLSocket socket)
    {
        return objects.remove(socket);
    }

    /**
     * Registers a SSLEngine with a provider.
     *
     * @param engine   the engine to register with the provider
     * @param provider the provider to register with the engine
     * @see #remove(SSLEngine)
     */
    public static void put(SSLEngine engine, Provider provider)
    {
        objects.put(engine, provider);
    }

    /**
     * @param engine an engine registered with {@link #put(SSLEngine, Provider)}
     * @return the provider registered with the given engine
     */
    public static Provider get(SSLEngine engine)
    {
        return objects.get(engine);
    }

    /**
     * Unregisters the given SSLEngine.
     *
     * @param engine the engine to unregister
     * @return the provider registered with the engine
     * @see #put(SSLEngine, Provider)
     */
    public static Provider remove(SSLEngine engine)
    {
        return objects.remove(engine);
    }

    /**
     * Base, empty, interface for providers.
     */
    public interface Provider
    {
    }

    /**
     * The client-side provider interface that applications must
     * implement to interact with the negotiation of the protocol.
     */
    public interface ClientProvider extends Provider
    {
        /**
         * Callback invoked to let the implementation know whether an
         * ALPN extension should be added to a ClientHello TLS message.
         *
         * @return true to add the ALPN extension, false otherwise
         */
        public boolean supports();

        /**
         * Callback invoked to let the implementation know the list
         * of protocols that should be added to the ALPN extension in
         * a ClientHello TLS message.
         * <p/>
         * This callback is invoked only if the {@link #supports()}
         * returned true.
         *
         * @return the list of protocols supported by the client;
         * if null or empty, the ALPN extension is not sent
         */
        public List<String> protocols();

        /**
         * Callback invoked to let the client application know that
         * the server does not support ALPN.
         */
        public void unsupported();

        /**
         * Callback invoked to let the client application know
         * the protocol chosen by the server.
         *
         * @param protocol the protocol selected by the server
         */
        public void selected(String protocol);
    }

    /**
     * The server-side provider interface that applications must
     * implement to interact with the negotiation of the protocol.
     */
    public interface ServerProvider extends Provider
    {
        /**
         * Callback invoked to let the server application know that
         * the client does not support ALPN.
         */
        public void unsupported();

        /**
         * Callback invoked to let the server application select
         * a protocol among the ones sent by the client.
         *
         * @param protocols the protocols sent by the client
         * @return the protocol selected by the server application;
         * must not be null
         */
        public String select(List<String> protocols);
    }
}
