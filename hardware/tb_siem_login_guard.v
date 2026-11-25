/*
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech CSE (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University,
Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
GitHub: https://github.com/Sarvepalliaudi
*/
`timescale 1ns/1ps
module tb_siem_login_guard;
    reg clk = 1'b0;
    reg reset_n = 1'b0;
    reg auth_fail_pulse = 1'b0;
    wire brute_force_irq;
    wire [15:0] alert_counter;
    integer i;

    always #5 clk = ~clk;

    siem_login_guard #(.WINDOW_CYCLES(100), .THRESHOLD(5)) dut (
        .clk(clk),
        .reset_n(reset_n),
        .auth_fail_pulse(auth_fail_pulse),
        .brute_force_irq(brute_force_irq),
        .alert_counter(alert_counter)
    );

    task pulse_failure;
        begin
            @(negedge clk);
            auth_fail_pulse = 1'b1;
            @(negedge clk);
            auth_fail_pulse = 1'b0;
        end
    endtask

    initial begin
        repeat (2) @(negedge clk);
        reset_n = 1'b1;
        for (i = 0; i < 4; i = i + 1)
            pulse_failure();
        if (alert_counter !== 16'd0)
            $fatal(1, "IRQ/counter asserted before threshold");
        pulse_failure();
        @(negedge clk);
        if (brute_force_irq !== 1'b1)
            $fatal(1, "expected brute-force IRQ on threshold crossing");
        if (alert_counter !== 16'd1)
            $fatal(1, "expected one alert after five failures, got %0d", alert_counter);
        @(negedge clk);
        if (brute_force_irq !== 1'b0)
            $fatal(1, "IRQ should be a one-cycle pulse");
        for (i = 0; i < 5; i = i + 1)
            pulse_failure();
        @(negedge clk);
        if (alert_counter !== 16'd2)
            $fatal(1, "expected second alert, got %0d", alert_counter);
        $display("PASS: threshold bursts incremented the alert counter");
        $finish;
    end
endmodule
