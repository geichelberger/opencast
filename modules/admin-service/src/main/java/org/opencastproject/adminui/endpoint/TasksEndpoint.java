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

package org.opencastproject.adminui.endpoint;

import static org.opencastproject.index.service.util.JSONUtils.safeString;
import static org.opencastproject.index.service.util.RestUtils.okJson;
import static org.opencastproject.workflow.api.ConfiguredWorkflow.workflow;

import org.opencastproject.assetmanager.api.AssetManager;
import org.opencastproject.assetmanager.util.Workflows;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;
import org.opencastproject.workflow.api.ConfiguredWorkflow;
import org.opencastproject.workflow.api.WorkflowDatabaseException;
import org.opencastproject.workflow.api.WorkflowDefinition;
import org.opencastproject.workflow.api.WorkflowInstance;
import org.opencastproject.workflow.api.WorkflowService;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/admin-ng/tasks")
@Tag(
    name = "Admin UI - Tasks",
    description = "Provides resources and operations related to the tasks"
)
@Component(
    immediate = true,
    service = TasksEndpoint.class,
    property = {
        "service.description=Admin UI - Tasks facade Endpoint",
        "opencast.service.type=org.opencastproject.adminui.endpoint.TasksEndpoint",
        "opencast.service.path=/admin-ng/tasks"
    }
)
@JaxrsResource
public class TasksEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(TasksEndpoint.class);

  private WorkflowService workflowService;

  private AssetManager assetManager;

  /** OSGi callback for the workflow service. */
  @Reference
  public void setWorkflowService(WorkflowService workflowService) {
    this.workflowService = workflowService;
  }

  /** OSGi callback to set the asset manager. */
  @Reference
  public void setAssetManager(AssetManager assetManager) {
    this.assetManager = assetManager;
  }

  @Activate
  protected void activate(BundleContext bundleContext) {
    logger.info("Activate tasks endpoint");
  }

  @GET
  @Path("processing.json")
  @Operation(
      summary = "Get the processing options for new tasks",
      description = "Returns all the data related to the processing tab in the new tasks modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the tasks processing tab as JSON"
      ),
      @ApiResponse(responseCode = "500", description = "The processing options could not be retrieved.")
  })
  public Response getProcessing(
      @Parameter(
          description = "A comma separated list of tags to filter the workflow definitions"
      )
      @QueryParam("tags") String tagsString
  ) {
    List<String> tags = RestUtil.splitCommaSeparatedParam(Optional.ofNullable(tagsString));

    JsonArray actions = new JsonArray();
    try {
      List<WorkflowDefinition> workflowDefinitions = workflowService.listAvailableWorkflowDefinitions();
      for (WorkflowDefinition wflDef : workflowDefinitions) {
        if (wflDef.containsTag(tags)) {
          JsonObject action = new JsonObject();
          action.addProperty("id", wflDef.getId());
          action.addProperty("title", safeString(wflDef.getTitle()));
          action.addProperty("description", safeString(wflDef.getDescription()));
          action.addProperty("configuration_panel", safeString(wflDef.getConfigurationPanel()));
          action.addProperty("configuration_panel_json", safeString(wflDef.getConfigurationPanelJson()));
          actions.add(action);
        }
      }
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get available workflow definitions", e);
      return RestUtil.R.serverError();
    }

    return okJson(actions);
  }

  @POST
  @Path("/new")
  @Operation(
      summary = "Create a new task",
      description = "Creates a new task by the given metadata as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Task sucessfully added"),
      @ApiResponse(responseCode = "404", description = "If the workflow definition is not found"),
      @ApiResponse(responseCode = "400", description = "If the metadata is not set or couldn't be parsed"),
      @ApiResponse(responseCode = "500", description = "The task could not be created.")
  })
  public Response createNewTask(
      @Parameter(
          description = "The metadata as JSON.<p>Example:<p>"
              + "<code><pre>{\n"
              + "  \"workflow\":\"republish-metadata\",\n"
              + "  \"configuration\":{\n"
              + "    \"ID-dual-stream-demo\":{\"workflowVar\":\"true\"},\n"
              + "    \"ID-about-opencast\":{\"workflowVar\":\"true\"}\n"
              + "  }\n"
              + "}</pre></code>",
          required = true
      )
      @FormParam("metadata") String metadata
  ) throws NotFoundException {
    if (StringUtils.isBlank(metadata)) {
      logger.warn("No metadata set");
      return RestUtil.R.badRequest("No metadata set");
    }
    Gson gson = new Gson();
    Map metadataJson;
    try {
      metadataJson = gson.fromJson(metadata, Map.class);
    } catch (Exception e) {
      logger.warn("Unable to parse metadata {}", metadata);
      return RestUtil.R.badRequest("Unable to parse metadata");
    }

    String workflowId = (String) metadataJson.get("workflow");
    if (StringUtils.isBlank(workflowId)) {
      return RestUtil.R.badRequest("No workflow set");
    }

    Map<String, Map<String, String>> configuration = (Map<String, Map<String, String>>) metadataJson
        .get("configuration");
    if (configuration == null) {
      return RestUtil.R.badRequest("No events set");
    }

    WorkflowDefinition wfd;
    try {
      wfd = workflowService.getWorkflowDefinitionById(workflowId);
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get workflow definition {}", workflowId, e);
      return RestUtil.R.serverError();
    }

    final Workflows workflows = new Workflows(assetManager, workflowService);
    final List<WorkflowInstance> instances = new ArrayList<>();
    for (final Entry<String, Map<String, String>> entry : configuration.entrySet()) {
      final ConfiguredWorkflow workflow = workflow(wfd, entry.getValue());
      final Set<String> mpIds = Collections.singleton(entry.getKey());
      final List<WorkflowInstance> partialResult = workflows.applyWorkflowToLatestVersion(mpIds, workflow);

      if (partialResult.size() != 1) {
        logger.warn("Couldn't start workflow for media package {}", entry.getKey());
        return Response.status(Status.BAD_REQUEST).build();
      }

      instances.addAll(partialResult);
    }
    return Response.status(Status.CREATED)
        .entity(gson.toJson(instances.stream().map(getWorkflowIds).collect(Collectors.toList())))
        .build();
  }

  private static final Function<WorkflowInstance, Long> getWorkflowIds = a -> a.getId();

}
