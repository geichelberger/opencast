/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.graphql.command;

import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.catalog.adapter.series.CommonSeriesCatalogUIAdapter;
import org.opencastproject.mediapackage.MediaPackageElementFlavor;
import org.opencastproject.metadata.dublincore.DublinCoreMetadataCollection;
import org.opencastproject.metadata.dublincore.MetadataField;
import org.opencastproject.metadata.dublincore.MetadataList;

import java.util.Map;

/**
 * Metadata handling shared by the commands that create or update events and series.
 */
final class MetadataSupport {

  private static final String SERIES_FLAVOR = "dublincore/series";

  private MetadataSupport() {
  }

  /**
   * Look up the field a client wants to set.
   *
   * @param collection the catalog's fields
   * @param key the name of the field given by the client
   * @param kind what the metadata belongs to, used in the error message (e.g. "series")
   * @return the field
   * @throws GraphQLRuntimeException of type {@link OpencastErrorType#BadRequest} if the catalog has no such field
   */
  static MetadataField requireField(DublinCoreMetadataCollection collection, String key, String kind) {
    final MetadataField field = collection.getOutputFields().get(key);
    if (field == null) {
      throw new GraphQLRuntimeException("Unknown " + kind + " metadata field '" + key + "'",
          OpencastErrorType.BadRequest);
    }
    return field;
  }

  /**
   * Create the series metadata list and apply the given values to it.
   */
  static MetadataList createSeriesMetadataList(Map<String, Object> seriesMetadata, IndexService indexService) {
    CommonSeriesCatalogUIAdapter adapter = (CommonSeriesCatalogUIAdapter) indexService
        .getCommonSeriesCatalogUIAdapter();

    MetadataList list = new MetadataList();
    list.add(adapter, adapter.getRawFields());

    final DublinCoreMetadataCollection collection = list.getMetadataByFlavor(
        MediaPackageElementFlavor.parseFlavor(SERIES_FLAVOR).toString());

    seriesMetadata.forEach((key, value) -> requireField(collection, key, "series").setValue(value));

    return list;
  }

}
