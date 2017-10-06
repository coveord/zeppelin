/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zeppelin.notebook;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.google.common.base.Predicate;
import com.google.common.collect.FluentIterable;
import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.notebook.repo.S3NotebookRepo;
import org.apache.zeppelin.user.AuthenticationInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contains authorization information for notes
 */
public class NotebookAuthorization {
  private static final Logger LOG = LoggerFactory.getLogger(NotebookAuthorization.class);
  private static NotebookAuthorization instance = null;
  /*
   * { "note1": { "owners": ["u1"], "readers": ["u1", "u2"], "writers": ["u1"] },  "note2": ... } }
   */
  private static Map<String, Map<String, Set<String>>> authInfo = new HashMap<>();
  /*
   * contains roles for each user
   */
  private static Map<String, Set<String>> userRoles = new HashMap<>();
  private static ZeppelinConfiguration conf;
  private static Gson gson;
  private static String filePath;
  private static AmazonS3 s3client;
  private static boolean useServerSideEncryption;

  private NotebookAuthorization() {
  }

  public static NotebookAuthorization init(ZeppelinConfiguration config) {
    if (instance == null) {
      instance = new NotebookAuthorization();
      conf = config;
      useServerSideEncryption = conf.isS3ServerSideEncryption();
      filePath = conf.getNotebookAuthorizationPath();
      GsonBuilder builder = new GsonBuilder();
      builder.setPrettyPrinting();
      gson = builder.create();
      try {
        s3client = S3NotebookRepo.createS3Client(conf);
        load();
      } catch (IOException e) {
        LOG.error("Error loading NotebookAuthorization", e);
      }
    }
    return instance;
  }

  public static NotebookAuthorization getInstance() {
    if (instance == null) {
      LOG.warn("Notebook authorization module was called without initialization,"
          + " initializing with default configuration");
      init(ZeppelinConfiguration.create());
    }
    return instance;
  }

  public static void load() throws IOException {
    LOG.info("filePath is " + filePath);
    if (filePath.startsWith("s3")) {
      loadFromS3();
    } else {
      loadFromFile();
    }
  }

  private static void loadFromS3() throws IOException {
    S3Object s3object;
    Pattern s3pattern = Pattern.compile("^s3://([^/]+)/(.*)$");
    Matcher s3matcher = s3pattern.matcher(filePath);
    String bucketName = "";
    String key = "";
    if (s3matcher.find()) {
      bucketName = s3matcher.group(1);
      key = s3matcher.group(2);
    }
    LOG.info("Loading notebook authorization from s3 with bucketName=" + bucketName
        + "and key=" + key);
    try {
      s3object = s3client.getObject(new GetObjectRequest(bucketName, key));
    } catch (AmazonClientException ace) {
      throw new IOException("Unable to retrieve object from S3: " + ace, ace);
    }
    try (InputStream ins = s3object.getObjectContent()) {
      String json = IOUtils.toString(ins,
          conf.getString(ZeppelinConfiguration.ConfVars.ZEPPELIN_ENCODING));
      NotebookAuthorizationInfoSaving info = gson.fromJson(json,
          NotebookAuthorizationInfoSaving.class);
      authInfo = info.authInfo;
    }
    LOG.info("Loading notebook authorization done!");
  }

  private static void loadFromFile() throws IOException {
    File settingFile = new File(filePath);
    LOG.info(settingFile.getAbsolutePath());
    if (!settingFile.exists()) {
      // nothing to read
      return;
    }
    FileInputStream fis = new FileInputStream(settingFile);
    InputStreamReader isr = new InputStreamReader(fis);
    BufferedReader bufferedReader = new BufferedReader(isr);
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = bufferedReader.readLine()) != null) {
      sb.append(line);
    }
    isr.close();
    fis.close();

    String json = sb.toString();

    NotebookAuthorizationInfoSaving info = gson.fromJson(json,
        NotebookAuthorizationInfoSaving.class);
    authInfo = info.authInfo;
  }

  public void setRoles(String user, Set<String> roles) {
    if (StringUtils.isBlank(user)) {
      LOG.warn("Setting roles for empty user");
      return;
    }
    roles = validateUser(roles);
    userRoles.put(user, roles);
  }

  public Set<String> getRoles(String user) {
    Set<String> roles = Sets.newHashSet();
    if (userRoles.containsKey(user)) {
      roles.addAll(userRoles.get(user));
    }
    return roles;
  }

  private void save() {
    if (filePath.startsWith("s3")) {
      saveToS3();
    } else {
      saveToFile();
    }
  }

  private void saveToS3() {
    Pattern s3pattern = Pattern.compile("^s3://([^/]+)/(.*)$");
    Matcher s3matcher = s3pattern.matcher(filePath);
    String bucketName = "";
    String key = "";
    if (s3matcher.find()) {
      bucketName = s3matcher.group(1);
      key = s3matcher.group(2);
    }

    String jsonString;

    synchronized (authInfo) {
      NotebookAuthorizationInfoSaving info = new NotebookAuthorizationInfoSaving();
      info.authInfo = authInfo;
      jsonString = gson.toJson(info);
    }

    try {
      File file = File.createTempFile("authorization", "json");
      try {
        Writer writer = new OutputStreamWriter(new FileOutputStream(file));
        writer.write(jsonString);
        writer.close();
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, key, file);
        if (useServerSideEncryption) {
          // Request server-side encryption.
          ObjectMetadata objectMetadata = new ObjectMetadata();
          objectMetadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
          putRequest.setMetadata(objectMetadata);
        }
        s3client.putObject(putRequest);
      } catch (AmazonClientException ace) {
        throw new IOException("Unable to store note in S3: " + ace, ace);
      } finally {
        FileUtils.deleteQuietly(file);
      }
    } catch (IOException e) {
      LOG.error("Error saving notebook authorization file: " + e.getMessage());
    }
  }

  private void saveToFile() {
    String jsonString;

    synchronized (authInfo) {
      NotebookAuthorizationInfoSaving info = new NotebookAuthorizationInfoSaving();
      info.authInfo = authInfo;
      jsonString = gson.toJson(info);
    }

    try {
      File settingFile = new File(filePath);
      if (!settingFile.exists()) {
        settingFile.createNewFile();
      }

      FileOutputStream fos = new FileOutputStream(settingFile, false);
      OutputStreamWriter out = new OutputStreamWriter(fos);
      out.append(jsonString);
      out.close();
      fos.close();
    } catch (IOException e) {
      LOG.error("Error saving notebook authorization file: " + e.getMessage());
    }
  }

  public boolean isPublic() {
    return conf.isNotebokPublic();
  }

  private Set<String> validateUser(Set<String> users) {
    Set<String> returnUser = new HashSet<>();
    for (String user : users) {
      if (!user.trim().isEmpty()) {
        returnUser.add(user.trim());
      }
    }
    return returnUser;
  }

  public void setOwners(String noteId, Set<String> entities) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    entities = validateUser(entities);
    if (noteAuthInfo == null) {
      noteAuthInfo = new LinkedHashMap();
      noteAuthInfo.put("owners", new LinkedHashSet(entities));
      noteAuthInfo.put("readers", new LinkedHashSet());
      noteAuthInfo.put("writers", new LinkedHashSet());
    } else {
      noteAuthInfo.put("owners", new LinkedHashSet(entities));
    }
    authInfo.put(noteId, noteAuthInfo);
    save();
  }

  public void setReaders(String noteId, Set<String> entities) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    entities = validateUser(entities);
    if (noteAuthInfo == null) {
      noteAuthInfo = new LinkedHashMap();
      noteAuthInfo.put("owners", new LinkedHashSet());
      noteAuthInfo.put("readers", new LinkedHashSet(entities));
      noteAuthInfo.put("writers", new LinkedHashSet());
    } else {
      noteAuthInfo.put("readers", new LinkedHashSet(entities));
    }
    authInfo.put(noteId, noteAuthInfo);
    save();
  }

  public void setWriters(String noteId, Set<String> entities) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    entities = validateUser(entities);
    if (noteAuthInfo == null) {
      noteAuthInfo = new LinkedHashMap();
      noteAuthInfo.put("owners", new LinkedHashSet());
      noteAuthInfo.put("readers", new LinkedHashSet());
      noteAuthInfo.put("writers", new LinkedHashSet(entities));
    } else {
      noteAuthInfo.put("writers", new LinkedHashSet(entities));
    }
    authInfo.put(noteId, noteAuthInfo);
    save();
  }

  public Set<String> getOwners(String noteId) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    Set<String> entities = null;
    if (noteAuthInfo == null) {
      entities = new HashSet<>();
    } else {
      entities = noteAuthInfo.get("owners");
      if (entities == null) {
        entities = new HashSet<>();
      }
    }
    return entities;
  }

  public Set<String> getReaders(String noteId) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    Set<String> entities = null;
    if (noteAuthInfo == null) {
      entities = new HashSet<>();
    } else {
      entities = noteAuthInfo.get("readers");
      if (entities == null) {
        entities = new HashSet<>();
      }
    }
    return entities;
  }

  public Set<String> getWriters(String noteId) {
    Map<String, Set<String>> noteAuthInfo = authInfo.get(noteId);
    Set<String> entities = null;
    if (noteAuthInfo == null) {
      entities = new HashSet<>();
    } else {
      entities = noteAuthInfo.get("writers");
      if (entities == null) {
        entities = new HashSet<>();
      }
    }
    return entities;
  }

  public boolean isOwner(String noteId, Set<String> entities) {
    return isMember(entities, getOwners(noteId));
  }

  public boolean isWriter(String noteId, Set<String> entities) {
    return isMember(entities, getWriters(noteId)) || isMember(entities, getOwners(noteId));
  }

  public boolean isReader(String noteId, Set<String> entities) {
    return isMember(entities, getReaders(noteId)) ||
        isMember(entities, getOwners(noteId)) ||
        isMember(entities, getWriters(noteId));
  }

  // return true if b is empty or if (a intersection b) is non-empty
  private boolean isMember(Set<String> a, Set<String> b) {
    Set<String> intersection = new HashSet<>(b);
    intersection.retainAll(a);
    return (b.isEmpty() || (intersection.size() > 0));
  }

  public boolean isOwner(Set<String> userAndRoles, String noteId) {
    if (conf.isAnonymousAllowed()) {
      LOG.debug("Zeppelin runs in anonymous mode, everybody is owner");
      return true;
    }
    if (userAndRoles == null) {
      return false;
    }
    return isOwner(noteId, userAndRoles);
  }

  public boolean hasWriteAuthorization(Set<String> userAndRoles, String noteId) {
    if (conf.isAnonymousAllowed()) {
      LOG.debug("Zeppelin runs in anonymous mode, everybody is writer");
      return true;
    }
    if (userAndRoles == null) {
      return false;
    }
    return isWriter(noteId, userAndRoles);
  }

  public boolean hasReadAuthorization(Set<String> userAndRoles, String noteId) {
    if (conf.isAnonymousAllowed()) {
      LOG.debug("Zeppelin runs in anonymous mode, everybody is reader");
      return true;
    }
    if (userAndRoles == null) {
      return false;
    }
    return isReader(noteId, userAndRoles);
  }

  public void removeNote(String noteId) {
    authInfo.remove(noteId);
    save();
  }

  public List<NoteInfo> filterByUser(List<NoteInfo> notes, AuthenticationInfo subject) {
    final Set<String> entities = Sets.newHashSet();
    if (subject != null) {
      entities.add(subject.getUser());
    }
    return FluentIterable.from(notes).filter(new Predicate<NoteInfo>() {
      @Override
      public boolean apply(NoteInfo input) {
        return input != null && isReader(input.getId(), entities);
      }
    }).toList();
  }

  public void setNewNotePermissions(String noteId, AuthenticationInfo subject) {
    if (!AuthenticationInfo.isAnonymous(subject)) {
      if (isPublic()) {
        // add current user to owners - can be public
        Set<String> owners = getOwners(noteId);
        owners.add(subject.getUser());
        setOwners(noteId, owners);
      } else {
        // add current user to owners, readers, writers - private note
        Set<String> entities = getOwners(noteId);
        entities.add(subject.getUser());
        setOwners(noteId, entities);
        entities = getReaders(noteId);
        entities.add(subject.getUser());
        setReaders(noteId, entities);
        entities = getWriters(noteId);
        entities.add(subject.getUser());
        setWriters(noteId, entities);
      }
    }
  }
}
