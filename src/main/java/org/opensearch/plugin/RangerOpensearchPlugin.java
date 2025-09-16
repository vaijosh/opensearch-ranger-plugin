/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensearch.plugin;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugin.action.filter.RangerSecurityActionFilter;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path; // Import Path
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/**
 * The main plugin class for Ranger OpenSearch integration.
 * This plugin implements {@link ActionPlugin} to provide action filtering capabilities
 * for security enforcement.
 */
public class RangerOpensearchPlugin extends Plugin implements ActionPlugin {
    private static final Logger LOG = LogManager.getLogger(RangerOpensearchPlugin.class);

    private static final String RANGER_OPENSEARCH_PLUGIN_CONF_NAME = "opensearch-ranger-plugin";
    private final Settings settings;

    private RangerSecurityActionFilter rangerSecurityActionFilter;

    /**
     * Constructs a new {@code RangerOpensearchPlugin}.
     *
     * @param settings The OpenSearch settings.
     */
    public RangerOpensearchPlugin(Settings settings) {
        this.settings = settings;
        LOG.debug("settings:{}", settings);
    }

    @Override
    public List<ActionFilter> getActionFilters() {
        return Collections.singletonList(rangerSecurityActionFilter);
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return null;
    }

    @Override
    public Collection<Object> createComponents(final Client client, final ClusterService clusterService, final ThreadPool threadPool, final ResourceWatcherService resourceWatcherService,
                                               final ScriptService scriptService, final NamedXContentRegistry xContentRegistry, final Environment environment, final NodeEnvironment nodeEnvironment,
                                               final NamedWriteableRegistry namedWriteableRegistry, IndexNameExpressionResolver indexNameExpressionResolver, Supplier<RepositoriesService> repositoriesServiceSupplier) {
        LOG.info("##Calling addPluginConfig2Classpath(environment)");
        addPluginConfig2Classpath(environment);

        rangerSecurityActionFilter = new RangerSecurityActionFilter(threadPool);

        return Collections.singletonList(rangerSecurityActionFilter);
    }

    /**
     * Add ranger opensearch plugin config directory to classpath,
     * then the plugin can load its configuration files from classpath.
     */
    private void addPluginConfig2Classpath(Environment environment) {
        Path configPath = environment.configFile().resolve(RANGER_OPENSEARCH_PLUGIN_CONF_NAME);

        if (configPath == null) {
            LOG.error("Failed to add ranger opensearch plugin config directory [ranger-opensearch-plugin] to classpath.");

            return;
        }

        File configFile = configPath.toFile();

        try {
            if (configFile.exists()) {
                ClassLoader classLoader = this.getClass().getClassLoader();

                // This classLoader is FactoryURLClassLoader in opensearch
                if (classLoader instanceof URLClassLoader) {
                    URLClassLoader                  urlClassLoader = (URLClassLoader) classLoader;
                    Class<? extends URLClassLoader> urlClass       = urlClassLoader.getClass();
                    Method                          method         = urlClass.getSuperclass().getDeclaredMethod("addURL", URL.class);

                    method.setAccessible(true);
                    method.invoke(urlClassLoader, configFile.toURI().toURL());

                    LOG.info("Success to add ranger opensearch plugin config directory [{}] to classpath.", configFile.getCanonicalPath());
                }
            }
        } catch (Exception e) {
            LOG.error("Failed to add ranger opensearch plugin config directory [ranger-opensearch-plugin] to classpath.", e);

            throw new RuntimeException(e);
        }
    }
}