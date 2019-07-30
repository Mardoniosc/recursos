/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javafxapplication11;

import eu.hansolo.medusa.FGauge;
import eu.hansolo.medusa.FGaugeBuilder;
import eu.hansolo.medusa.Gauge;
import eu.hansolo.medusa.GaugeBuilder;
import eu.hansolo.medusa.GaugeDesign;
import eu.hansolo.medusa.skins.ModernSkin;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.paint.Color;

/**
 *
 * @author P772920
 */
public class FXMLDocumentController implements Initializable {
    
    private Label label;
    @FXML
    private Gauge gaugeExample;
    @FXML
    private Gauge gaugeExample2;
    @FXML
    private Gauge gaugeExample3;
    @FXML
    private Gauge gaugeExample4;

    
    private void handleButtonAction(ActionEvent event) {
        System.out.println("You clicked me!");
        label.setText("Hello World!");
    }
    

    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        gaugeExample.setValue(80.6);
        gaugeExample3.setValue(60.0);
        gaugeExample3.setUnit("Mardonio");
        gaugeExample2.setTitle("Velocimetro");
        
        gaugeExample.setSkin(new ModernSkin(gaugeExample));
        
    }

    
 
    
    
}
