package com.mx.echavez.virustotal;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.tomcat.util.json.JSONParser;
import org.apache.tomcat.util.json.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Service
public class VirusTotalService {

	Logger logger = LoggerFactory.getLogger(VirusTotalService.class);

	@Value("${virustotal.key.api}")
	private String apiKey;

	@SuppressWarnings("deprecation")
	public String llamarAnalizador(String archivo) throws IOException, URISyntaxException, ParseException {

		OkHttpClient client = new OkHttpClient();
		
		URL url = new VirusTotalService().getClass().getClassLoader().getResource(archivo);

		MultipartBody.Builder builder = new MultipartBody.Builder();
		builder.setType(MultipartBody.FORM);
		File file = new File(url.toURI());
		if (!file.canRead()) {
			throw new IOException("No se puede leer el archivo");
		}
		logger.debug("Total de espacio {}", file.getTotalSpace());
		builder.addFormDataPart("file", file.getName(),
				RequestBody.create(MediaType.parse("application/octet-stream"), file));

		RequestBody requestBody = builder.build();

		Request request = new Request.Builder().url("https://www.virustotal.com/api/v3/files").post(requestBody)
				.addHeader("accept", "application/json").addHeader("x-apikey", apiKey)
				.addHeader("content-type", "multipart/form-data").build();

		Response response = client.newCall(request).execute();
		String respuesta = response.body().string();
		logger.info("Codigo {} ", response.code());
		logger.info("Respuesta {}", respuesta);

		JSONParser parser = new JSONParser(respuesta);
		LinkedHashMap<String, Object> json = parser.object();
		Object itemsObject = json.get("data");
		@SuppressWarnings("unchecked")
		LinkedHashMap<String, Object> pod = (LinkedHashMap<String, Object>) itemsObject;
		return pod.get("id").toString();

	}

	public String getAnalysis(String id) throws Exception {
		OkHttpClient client = new OkHttpClient();
		Request request = new Request.Builder().url("https://www.virustotal.com/api/v3/analyses/" + id)
				.addHeader("accept", "application/json").addHeader("x-apikey", apiKey).build();
		Response response = client.newCall(request).execute();
		String respuesta = response.body().string();
		if (response.code() != 200) {
			throw new Exception("No se pudo recuperar el análisis");
		}
		logger.info("Codigo {} : Respuesta {}", response.code(), respuesta);
		return respuesta;
	}

	public static Map<String, Object> convertJsonIntoMap(String jsonFile) {
		Map<String, Object> map = new HashMap<>();
		try {
			ObjectMapper mapper = new ObjectMapper();
			map = mapper.readValue(jsonFile, new TypeReference<Map<String, Object>>() {
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
		return map;
	}

}
