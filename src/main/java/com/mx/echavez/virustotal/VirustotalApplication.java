package com.mx.echavez.virustotal;

import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@SpringBootApplication
@Controller
public class VirustotalApplication {

	Logger logger = LoggerFactory.getLogger(VirustotalApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(VirustotalApplication.class, args);
	}

	@Autowired
	private VirusTotalService virusTotalService;

	@GetMapping("/")
	public ModelAndView home(ModelAndView model) {
		try {
			// Cambiar el nombre del archivo a escanear este debe estar en la carpeta de
			// resources
			String fileName = "ejemplo_vacaciones_ajuste.csv";
			String id=virusTotalService.llamarAnalizador(fileName);
			String mapa = virusTotalService.getAnalysis(id);
			model.addObject("mapa", mapa);
			model.addObject("fileName", fileName);
		} catch (Exception e) {
			logger.error("Ocurrio un error al ejecutar", e);
		}
		model.setViewName("home");
		return model;
	}

}
