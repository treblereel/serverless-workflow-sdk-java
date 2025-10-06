/*
 * Copyright 2020-Present The Serverless Workflow Specification Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.serverlessworkflow.fluent.agentic.langchain4j;

import static io.serverlessworkflow.fluent.agentic.AgentWorkflowBuilder.workflow;
import static io.serverlessworkflow.fluent.agentic.Agents.*;
import static io.serverlessworkflow.fluent.agentic.AgentsUtils.*;
import static io.serverlessworkflow.fluent.agentic.langchain4j.Agents.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import dev.langchain4j.agentic.scope.AgenticScope;
import io.serverlessworkflow.fluent.agentic.AgenticServices;
import io.serverlessworkflow.fluent.agentic.AgentsUtils;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

public class AgenticServicesHelperTest {

  @Test
  public void sequenceHelperTest() {
    var creativeWriter = newCreativeWriter();
    var audienceEditor = newAudienceEditor();
    var styleEditor = newStyleEditor();

    NovelCreator novelCreator =
        io.serverlessworkflow.fluent.agentic.AgenticServices.of(NovelCreator.class)
            .flow(workflow("seqFlow").sequence(creativeWriter, audienceEditor, styleEditor))
            .build();

    String story = novelCreator.createNovel("dragons and wizards", "young adults", "fantasy");
    assertNotNull(story);
  }

  @Test
  public void agentAndSequenceHelperTest() {
    var creativeWriter = newCreativeWriter();
    var audienceEditor = newAudienceEditor();
    var styleEditor = newStyleEditor();

    NovelCreator novelCreator =
        io.serverlessworkflow.fluent.agentic.AgenticServices.of(NovelCreator.class)
            .flow(workflow("seqFlow").agent(creativeWriter).sequence(audienceEditor, styleEditor))
            .build();

    String story = novelCreator.createNovel("dragons and wizards", "young adults", "fantasy");
    assertNotNull(story);
  }

  @Test
  public void agentAndSequenceAndAgentHelperTest() {
    var creativeWriter = newCreativeWriter();
    var audienceEditor = newAudienceEditor();
    var styleEditor = newStyleEditor();
    var summaryStory = newSummaryStory();

    NovelCreator novelCreator =
        io.serverlessworkflow.fluent.agentic.AgenticServices.of(NovelCreator.class)
            .flow(
                workflow("seqFlow")
                    .agent(creativeWriter)
                    .sequence(audienceEditor, styleEditor)
                    .agent(summaryStory))
                .build();

    String story = novelCreator.createNovel("dragons and wizards", "young adults", "fantasy");
    assertNotNull(story);
  }

  @Test
  public void parallelWorkflow() {
    var foodExpert = newFoodExpert();
    var movieExpert = newMovieExpert();

    Function<Map<String, List<String>>, List<EveningPlan>> planEvening =
        input -> {
          List<String> movies = input.get("findMovie");
          List<String> meals = input.get("findMeal");

          int max = Math.min(movies.size(), meals.size());
          return IntStream.range(0, max)
                  .mapToObj(i -> new EveningPlan(movies.get(i), meals.get(i)))
                  .toList();
        };

    EveningPlannerAgent eveningPlannerAgent =
        AgenticServices.of(EveningPlannerAgent.class)
            .flow(workflow("parallelFlow").parallel(foodExpert, movieExpert)
                    .outputAs(planEvening)
            )
                .outputName("input")
            .build();
    List<EveningPlan> result = eveningPlannerAgent.plan("romantic");
    assertEquals(3, result.size());
  }

  @Test
  public void loopTest() {
    var creativeWriter = AgentsUtils.newCreativeWriter();
    var scorer = AgentsUtils.newStyleScorer();
    var editor = AgentsUtils.newStyleEditor();

    Predicate<AgenticScope> until = s -> s.readState("score", 0.0) >= 0.8;

    StyledWriter styledWriter =
        AgenticServices.of(StyledWriter.class)
            .flow(workflow("loopFlow").agent(creativeWriter).loop(until, scorer, editor))
                .outputName("story")
            .build();

    String story = styledWriter.writeStoryWithStyle("dragons and wizards", "fantasy");
    assertNotNull(story);
  }

  @Test
  public void humanInTheLoop() {
    var astrologyAgent = newAstrologyAgent();

    var askSign =
        new Function<Map<String, Object>, Map<String, Object>>() {
          @Override
          public Map<String, Object> apply(Map<String, Object> holder) {
            System.out.println("What's your star sign?");
            // var sign = System.console().readLine();
            holder.put("sign", "piscis");
            return holder;
          }
        };

    String result =
        AgenticServices.of(HoroscopeAgent.class)
            .flow(
                workflow("humanInTheLoop")
                    .inputFrom(askSign)
                    // .tasks(tasks -> tasks.callFn(fn(askSign))) // TODO should work too
                    .agent(astrologyAgent))
            .build()
            .invoke("My name is Mario. What is my horoscope?");

    assertNotNull(result);
  }
}
