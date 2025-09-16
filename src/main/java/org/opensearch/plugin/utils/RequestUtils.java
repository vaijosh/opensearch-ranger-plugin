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
 * this work for additional information regarding copyright ownership.
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

package org.opensearch.plugin.utils;

import org.apache.commons.collections.CollectionUtils;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.admin.indices.cache.clear.ClearIndicesCacheRequest;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.flush.FlushRequest;
import org.opensearch.action.admin.indices.forcemerge.ForceMergeRequest;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.mapping.get.GetFieldMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.admin.indices.open.OpenIndexRequest;
import org.opensearch.action.admin.indices.recovery.RecoveryRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.segments.IndicesSegmentsRequest;
import org.opensearch.action.admin.indices.settings.get.GetSettingsRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.admin.indices.shards.IndicesShardStoresRequest;
import org.opensearch.action.admin.indices.shrink.ResizeRequest;
import org.opensearch.action.admin.indices.stats.IndicesStatsRequest;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.admin.indices.upgrade.get.UpgradeStatusRequest;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeRequest;
import org.opensearch.action.admin.indices.validate.query.ValidateQueryRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetRequest.Item;
import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.replication.ReplicationRequest;
import org.opensearch.action.support.single.instance.InstanceShardOperationRequest;
import org.opensearch.action.support.single.shard.SingleShardRequest;
import org.opensearch.action.termvectors.MultiTermVectorsRequest;
import org.opensearch.action.termvectors.TermVectorsRequest;
import org.opensearch.common.network.NetworkAddress;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.index.reindex.UpdateByQueryRequest;
import org.opensearch.rest.RestRequest;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for processing OpenSearch requests.
 * Provides methods to extract client IP addresses and indices from various request types.
 */
public class RequestUtils {
    /**
     * Constant for the client IP address header.
     */
    public static final String CLIENT_IP_ADDRESS = "ClientIPAddress";

    /**
     * Private constructor to prevent instantiation.
     */
    private RequestUtils() {
        // to block instantiation
    }

    /**
     * Retrieves the client IP address from a {@link RestRequest}.
     *
     * @param request The REST request from which to extract the IP address.
     * @return A string representation of the client's IP address.
     * @throws IllegalArgumentException If the socket address is not an {@link InetSocketAddress}.
     */
    public static String getClientIPAddress(RestRequest request) {
        SocketAddress socketAddress = request.getHttpChannel().getRemoteAddress();
        if (socketAddress instanceof InetSocketAddress) {
            // Use NetworkAddress.format() directly with the InetSocketAddress
            // It will return the IP address (and potentially port if needed, depending on the overload)
            return NetworkAddress.format((InetSocketAddress) socketAddress);
        } else {
            // Handle other types of SocketAddress if necessary, or throw an exception
            // For example, if you only expect InetSocketAddress:
            throw new IllegalArgumentException("Expected InetSocketAddress, but got: " + socketAddress.getClass().getName());
            // Or return a default/error string:
            // return "Unknown Address Type";
        }
    }

    /**
     * Extracts a list of index names from various types of OpenSearch {@link ActionRequest}s.
     * If the request type is not matched, it defaults to returning a list containing "*".
     *
     * @param request The action request from which to extract index names.
     * @param <Request> The type of the action request, must extend {@link ActionRequest}.
     * @return A list of strings representing the index names involved in the request.
     */
    // To support all kinds of request in opensearch
    public static <Request extends ActionRequest> List<String> getIndexFromRequest(Request request) {
        List<String> indexs = new ArrayList<>();

        if (request instanceof SingleShardRequest) {
            indexs.add(((SingleShardRequest<?>) request).index());

            return indexs;
        }

        if (request instanceof ReplicationRequest) {
            indexs.add(((ReplicationRequest<?>) request).index());

            return indexs;
        }

        if (request instanceof InstanceShardOperationRequest) {
            indexs.add(((InstanceShardOperationRequest<?>) request).index());

            return indexs;
        }

        if (request instanceof CreateIndexRequest) {
            indexs.add(((CreateIndexRequest) request).index());

            return indexs;
        }

        if (request instanceof PutMappingRequest) {
            if (((PutMappingRequest) request).getConcreteIndex() != null) {
                indexs.add(((PutMappingRequest) request).getConcreteIndex().getName());

                return indexs;
            } else {
                return Arrays.asList(((PutMappingRequest) request).indices());
            }
        }

        if (request instanceof SearchRequest) {
            return Arrays.asList(((SearchRequest) request).indices());
        }

        if (request instanceof IndicesStatsRequest) {
            return Arrays.asList(((IndicesStatsRequest) request).indices());
        }

        if (request instanceof OpenIndexRequest) {
            return Arrays.asList(((OpenIndexRequest) request).indices());
        }

        if (request instanceof DeleteIndexRequest) {
            return Arrays.asList(((DeleteIndexRequest) request).indices());
        }

        if (request instanceof BulkRequest) {
            @SuppressWarnings("rawtypes") List<DocWriteRequest<?>> requests = ((BulkRequest) request).requests();

            if (CollectionUtils.isNotEmpty(requests)) {
                for (DocWriteRequest<?> docWriteRequest : requests) {
                    indexs.add(docWriteRequest.index());
                }

                return indexs;
            }
        }

        if (request instanceof MultiGetRequest) {
            List<Item> items = ((MultiGetRequest) request).getItems();

            if (CollectionUtils.isNotEmpty(items)) {
                for (Item item : items) {
                    indexs.add(item.index());
                }

                return indexs;
            }
        }

        if (request instanceof GetMappingsRequest) {
            return Arrays.asList(((GetMappingsRequest) request).indices());
        }

        if (request instanceof GetSettingsRequest) {
            return Arrays.asList(((GetSettingsRequest) request).indices());
        }

        if (request instanceof IndicesExistsRequest) {
            return Arrays.asList(((IndicesExistsRequest) request).indices());
        }

        if (request instanceof GetAliasesRequest) {
            return Arrays.asList(((GetAliasesRequest) request).indices());
        }

        if (request instanceof GetIndexRequest) {
            return Arrays.asList(((GetIndexRequest) request).indices());
        }

        if (request instanceof GetFieldMappingsRequest) {
            return Arrays.asList(((GetFieldMappingsRequest) request).indices());
        }

        if (request instanceof ValidateQueryRequest) {
            return Arrays.asList(((ValidateQueryRequest) request).indices());
        }

        if (request instanceof RecoveryRequest) {
            return Arrays.asList(((RecoveryRequest) request).indices());
        }

        if (request instanceof IndicesSegmentsRequest) {
            return Arrays.asList(((IndicesSegmentsRequest) request).indices());
        }

        if (request instanceof IndicesShardStoresRequest) {
            return Arrays.asList(((IndicesShardStoresRequest) request).indices());
        }

        if (request instanceof UpgradeStatusRequest) {
            return Arrays.asList(((UpgradeStatusRequest) request).indices());
        }

        if (request instanceof ClusterSearchShardsRequest) {
            return Arrays.asList(((ClusterSearchShardsRequest) request).indices());
        }

        if (request instanceof IndicesAliasesRequest) {
            List<IndicesAliasesRequest.AliasActions> aliasActions = ((IndicesAliasesRequest) request).getAliasActions();

            if (CollectionUtils.isNotEmpty(aliasActions)) {
                for (IndicesAliasesRequest.AliasActions action : aliasActions) {
                    indexs.addAll(Arrays.asList(action.indices()));
                }

                return indexs;
            }
        }

        if (request instanceof ClearIndicesCacheRequest) {
            return Arrays.asList(((ClearIndicesCacheRequest) request).indices());
        }

        if (request instanceof CloseIndexRequest) {
            return Arrays.asList(((CloseIndexRequest) request).indices());
        }

        if (request instanceof FlushRequest) {
            return Arrays.asList(((FlushRequest) request).indices());
        }

        if (request instanceof ForceMergeRequest) {
            return Arrays.asList(((ForceMergeRequest) request).indices());
        }

        if (request instanceof RefreshRequest) {
            return Arrays.asList(((RefreshRequest) request).indices());
        }

        if (request instanceof RolloverRequest) {
            return Arrays.asList(((RolloverRequest) request).indices());
        }

        if (request instanceof UpdateSettingsRequest) {
            return Arrays.asList(((UpdateSettingsRequest) request).indices());
        }

        if (request instanceof ResizeRequest) {
            return Arrays.asList(((ResizeRequest) request).indices());
        }

        if (request instanceof DeleteIndexTemplateRequest) {
            indexs.add(((DeleteIndexTemplateRequest) request).name());
            return indexs;
        }

        if (request instanceof GetIndexTemplatesRequest) {
            return Arrays.asList(((GetIndexTemplatesRequest) request).names());
        }

        if (request instanceof PutIndexTemplateRequest) {
            indexs.add(((PutIndexTemplateRequest) request).name());
            return indexs;
        }

        if (request instanceof UpgradeRequest) {
            return Arrays.asList(((UpgradeRequest) request).indices());
        }

        if (request instanceof FieldCapabilitiesRequest) {
            return Arrays.asList(((FieldCapabilitiesRequest) request).indices());
        }

        if (request instanceof MultiSearchRequest) {
            List<SearchRequest> searchRequests = ((MultiSearchRequest) request).requests();

            if (CollectionUtils.isNotEmpty(searchRequests)) {
                for (SearchRequest singleRequest : searchRequests) {
                    indexs.addAll(Arrays.asList(singleRequest.indices()));
                }

                return indexs;
            }
        }

        if (request instanceof MultiTermVectorsRequest) {
            List<TermVectorsRequest> termVectorsRequests = ((MultiTermVectorsRequest) request).getRequests();

            if (CollectionUtils.isNotEmpty(termVectorsRequests)) {
                for (TermVectorsRequest singleRequest : termVectorsRequests) {
                    indexs.addAll(Arrays.asList(singleRequest.indices()));
                }

                return indexs;
            }
        }

        if (request instanceof UpdateByQueryRequest) {
            return Arrays.asList(((UpdateByQueryRequest) request).indices());
        }

        if (request instanceof DeleteByQueryRequest) {
            return Arrays.asList(((DeleteByQueryRequest) request).indices());
        }

        if (request instanceof ReindexRequest) {
            indexs.addAll(Arrays.asList(((ReindexRequest) request).getSearchRequest().indices()));
            indexs.addAll(Arrays.asList(((ReindexRequest) request).getDestination().indices()));

            return indexs;
        }

        //ClearScrollRequest does not carry any index, so return empty List
        if (request instanceof ClearScrollRequest) {
            return indexs;
        }

        // No matched request type to find specific index , set default value *
        indexs.add("*");

        return indexs;
    }
}