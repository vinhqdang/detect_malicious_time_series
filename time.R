detect_ana_mean <- function (x, window_size = 10, alpha = 0.05) {
  N <- length (x)
  outlier_ids <- c()
  for (i in (window_size:N)) {
    # print (i)
    begin_point = i - window_size + 1
    end_point = i
    cur_y <- x[begin_point:end_point]
    # print (cur_y)
    cur_x <- 1:window_size
    l1 <- summary (lm (cur_y ~ cur_x))
    if (l1$coefficients[2,][4] < alpha) {
      print (i)
      outlier_ids <- c(outlier_ids, i)
      print (l1)
      readline(prompt="Press [enter] to continue")
    }
  }
  outlier_ids
}

detect_anomaly_autoencoder <- function (df) {
  require(h2o)
  h2o.init()
  
  df_h <- as.h2o (df)
  df_d <- h2o.deeplearning(x=1:ncol(df), training_frame = df_h, autoencoder = TRUE,
                           activation = "Tanh", hidden = c(64,64,64), epochs = 100)
  errors <- h2o.anomaly(df_d, df_h, per_feature = TRUE)
  er <- as.data.frame (errors)
  # plot (er$reconstr_diff.SE)
  # lines (er$reconstr_avg.SE, col = "red")
  
  print (paste("Correct:", min(which(df$malicious==1))))
  
  require(AnomalyDetection)
  res <- AnomalyDetectionVec(x = er$reconstr_avg.SE, period =5, plot = TRUE, max_anoms = 0.05)
  print (res)
  
  
  # require("tsoutliers")
  # ts1 <- ts (er$reconstr_avg.SE)
  # print (tso (ts1))
  h2o.shutdown(prompt = FALSE)
}

running_average <- function (x, average_size) {
  # sapply(average_size:(length(x)-average_size), function(i) mean(x[(i-average_size):(i+average_size)]))
  sapply(average_size:length(x), function(i) mean(x[(i-average_size):(i)]))
}

detect_anomaly_series <- function (
  x,   # input vector
  average_size = 5, # window size (both ways) to calculate the mean
  down_threshold = 20, # how many times the value goes down before deciding malicious
  down_rate = 1.0,    # if the value goes down down_rate (percent) we decide it is malicious,
  decrease = TRUE     # find decreasing or increasing subsequence
) {
  x1 <- sapply((max(1, average_size)):(length(x)-average_size), function(i) mean(x[(i-average_size):(i+average_size)]))
  # x1 <- x
  N = length (x1)
  
  # print (x1)
  plot (x)
  lines (x1, col = "red")
  output <- c()
  for (i in down_threshold:N) {
    down_count <- 0
    if (decrease == TRUE) {
      down_count <- sum (diff(x1[max(1,i-down_threshold):i]) < 0)
    } else {
      down_count <- sum (diff(x1[max(1,i-down_threshold):i]) > 0)
    }
    # print (paste(i, ":", down_count))
    if (down_count >= (down_rate * down_threshold)) {
      output <- c(output, i)
    }
  }
  abline (v = output[1], lty = 2)
  output
}

detect_anomaly_avg <- function (avg,
                                num,
                                multiple_ratio = 2,
                                min_malicious_num = 150,
                                correct_mal_pos = 0,
                                num_mal = 0,
                                upper_bound = 17.5,
                                streak_len =10
                                ) 
{
  # B <- 0.001215 * 3 # 0.00125 is a slope of avg on num, generated from data 11k lines
  # A <- 0.429325
  
  # find the correlation between avg ~ num in normal situation
  # x <- num[50:min_malicious_num]
  # y <- avg[50:min_malicious_num]
  # l1 <- lm (y ~ x)
  # 
  # A <- as.numeric(l1$coefficients[1])
  # B <- abs(as.numeric(l1$coefficients[2])) * multiple_ratio
  # 
  # if (length(avg) != length(num)) {
  #   print ("Different length")
  #   stop()
  # }
  
  N <- length (avg)
  output <- c()
  for (i in streak_len:N) {
    s <- sum (avg[max(1,(i-streak_len)):i] / upper_bound, na.rm = TRUE)
    if (s > streak_len * 2) {
      output <- c(output, i)
    }
  }
  # plot (avg ~ num, main = paste("Number of malicious", num_mal, ". Correct pos:", correct_mal_pos))
  # # abline (a = A, b = B, col = "red")
  # 
  # abline (h = upper_bound, col = "red")
  # # remove accident peak points
  # abline (v = output[1], lty = 2)
  # abline (v = correct_mal_pos, lty = 2, col = "blue")
  output
}

find_longest_decrease <- function (x) {
  N <- length (x)
  output <- c() #length (output) should be = N
  for (i in 1:N) {
    if (i %% 1000 == 0) {
      print (paste ("Process data number", i))
      print (paste("Current maximum:", max(output)))
      print (paste("Index of max:", min(which (output == max(output)))))
    }
    cur_decrease <- 0
    if (i == 1) {
      for (j in 1:(N-i)) {
        if ((i+j) <= N & x[i+j-1] > x[i+j]) {
          cur_decrease <- cur_decrease + 1
        } else {
          break()
        }
      }
    } else if (i > 1 & output [i-1] == 0) {
      for (j in 1:(N-i)) {
        if ((i+j) <= N & x[i+j-1] > x[i+j]) {
          cur_decrease <- cur_decrease + 1
        } else {
          break()
        }
      }
    } else {
      cur_decrease <- output[i-1] - 1
    }
    output <- c (output, cur_decrease)
  }
  output
}

# implement naive Brute Force Euclidean Distance in 
# "Jones, M.J.; Nikovski, D.N.; Imamura, M.; Hirata, T., 
# "Exemplar Learning for Extremely Efficient Anomaly Detection in Real-Valued Time Series", 
# Journal of Data Mining and Knowledge Discovery, 
# DOI: 10.1007/s10618-015-0449-3, ISSN: 1573-756X, Vol. 30, No. 6, pp. 1427-1454, March 2016."
BFED <- function (train_series, test_series, subsequence_len)
{
  # train_series: T[1..n]: no anomaly
  # test_series: Q[1..m]
  # subsequence_len: w
  # output: vector S[1..m-w] as anomaly score
  n <- length(train_series)
  m <- length(test_series)
  w <- subsequence_len
  S <- c()
  for (i in 1:(m-w)) {
    bsf <- Inf
    for (j in 1:(n-w)) {
      d <- 0
      for (k in 1:w) {
        d <- d + (train_series[j+k] - test_series[i+k])^2
        if (d < bsf) {
          bsf <- d
        }
      }
    }
    S <- c(S, bsf)
  }
  S
}

# detect malicious using all available information
detect_all_information <- function (path = "/Users/qdang/workspace/Trusternity-client/data/2/",
                                    alpha = 0.5) 
{
  # manual from https://github.com/coast-team/Trusternity-client/tree/master/data
  # malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 265, 245,
  #                       230, 251, 245, 227, 239, 223, 218, 253, 251)
  malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 232, 245,
                        230, 251, 245, 227, 239, 223, 209, 253, 251)
  df <- data.frame("number_of_malicious" = as.numeric(),
                   "malicious_start" = as.numeric(),
                   "malicious_predict" =as.numeric(),
                   "mean_high_avg" = as.numeric(),
                   "high_avg_start" = as.numeric(),
                   "longest_down_streak" = as.numeric(),
                   "longest_down_streak_position" = as.numeric(),
                   "time_error" = as.numeric()   # different in minute between actual malicious point and prediction
                   )
  for (i in 1:19) {
    print (paste("Processing",i))
    if (i == 9 | i == 15) {
      path = "/Users/qdang/workspace/Trusternity-client/data/7/"
    } else {
      path = "/Users/qdang/workspace/Trusternity-client/data/2/"
    }
    file_name = paste(path,"blocks_info_40-",i,".json.csv", sep = "")
    cur_df <- read.csv(file_name)
    S1 <- find_longest_decrease(running_average(cur_df$diff, average_size = 5))
    S2 <- cur_df[cur_df$avg >= 20 & cur_df$num >= 20,]$avg
    
    high_avg_start <- min (which(cur_df$avg == max(S2)))
    longest_down_streak_position <- min (which (S1 == max(S1)))
    predict_pos <- high_avg_start * alpha + longest_down_streak_position * (1-alpha)
    
    new_row <- c(i, 
                 malicious_start[i],
                 predict_pos,
                 mean (S2),
                 high_avg_start,
                 max(S1),
                 longest_down_streak_position,
                 abs (cur_df$time[round(malicious_start[i])] - cur_df$time[predict_pos]) / 60
                 )
    df[nrow(df) + 1,] <- new_row
  }
  df$error <- abs(df$malicious_predict - df$malicious_start)
  # df$time_error <- abs (df$time[df$malicious_predict] - df$time[df$malicious_start])
  
  plot (df$error ~ df$number_of_malicious, col = "red", xlim = c(1,19), ylim =c(0,200), type = "o", ylab = "Value", xlab = "Number of malicious", lty = 3)
  lines (df$mean_high_avg ~ df$number_of_malicious, col = "black", lty = 2, type = "o", pch = 2)
  lines (df$longest_down_streak ~ df$number_of_malicious, col = "blue", lty = 1, type = "o", pch = 3)
  lines (df$time_error ~ df$number_of_malicious, col = "purple", lty = 4, pch = 4, type = "o")
  
  legend(x=5,y=200,col = c("red","black","blue","purple"), lty=c(3,2,1,4), c("Prediction error (number of blocks)","Average number of block","Longest down streak",
                                                                              "Prediction error (minutes)"),
              pch = c(1,2,3,4))
  
  df
}

detect_regression_avg_time <- function (path = "/Users/qdang/workspace/Trusternity-client/data/2/",
                                    mul_ratio = 2,
                                    min_malicious_start = 150,
                                    predict_index = 1) 
{
  # manual from https://github.com/coast-team/Trusternity-client/tree/master/data
  # malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 265, 245,
  #                       230, 251, 245, 227, 239, 223, 218, 253, 251)
  malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 227, 245,
                        230, 251, 245, 227, 239, 223, 245, 237, 210)
  df <- data.frame("number_of_malicious" = as.numeric(),
                   "malicious_start" = as.numeric(),
                   "malicious_predict" =as.numeric(),
                   "time_error" = as.numeric()   # different in minute between actual malicious point and prediction
  )
  for (i in 1:19) {
    # print (paste("Processing",i))
    if (i == 9 | i == 15 | i == 18 | i == 19) {
      path = "/Users/qdang/workspace/Trusternity-client/data/8/"
    } else {
      path = "/Users/qdang/workspace/Trusternity-client/data/2/"
    }
    file_name = paste(path,"blocks_info_40-",i,".json.csv", sep = "")
    cur_df <- read.csv(file_name)
    
    predict_pos <- detect_anomaly_avg(avg = cur_df$avg, num = cur_df$num, multiple_ratio = mul_ratio, min_malicious_num = min_malicious_start,
                                      num_mal = i, correct_mal_pos = malicious_start[i])
    
    p_index = min (length(predict_pos), predict_index)
    new_row <- c(i, 
                 malicious_start[i],
                 predict_pos[p_index],
                 (cur_df$time[predict_pos[p_index]] - cur_df$time[round(malicious_start[i])]) / 60
    )
    df[nrow(df) + 1,] <- new_row
  }
  df$error <- df$malicious_predict - df$malicious_start
  # df$time_error <- abs (df$time[df$malicious_predict] - df$time[df$malicious_start])
  
  plot (abs(df$error) ~ df$number_of_malicious, col = "red", xlim = c(1,20), ylim =c(-0,50),
        type = "o", ylab = "Value", xlab = "Number of malicious", lty = 3, xaxt = "n")
  axis(1, at=1:20, labels=1:20)
  # lines (df$mean_high_avg ~ df$number_of_malicious, col = "black", lty = 2, type = "o", pch = 2)
  # lines (df$longest_down_streak ~ df$number_of_malicious, col = "blue", lty = 1, type = "o", pch = 3)
  lines (abs(df$time_error) ~ df$number_of_malicious, col = "black", lty = 4, pch = 4, type = "o")
  
  legend(x=5,y=50,col = c("red","black"), lty=c(3,4), c("Prediction error (number of blocks)",
                                                                             "Prediction error (minutes)"),
         pch = c(1,4))
  
  print (paste("Time:", mean (abs(df$time_error))))
  print (paste("Block:", mean (abs(df$error))))
  print (paste("Negative count:", sum (df$time_error <0) + sum (df$error < 0)))
  df
}

run_all_regression <- function ()
{
  mul_ratios <- seq(1,2,.25)
  min_mals <- c(200)
  p_indexes <- seq(15,25,1)
  
  avg_time <- c()
  avg_block <- c()
  neg_count <- c()
  
  for (mul in mul_ratios) {
    for (min_mal in min_mals) {
      for (p_index in p_indexes) {
        x <- detect_regression_avg_time(mul_ratio = mul, min_malicious_start = min_mal, predict_index = p_index)
        avg_time <- c(avg_time, mean (abs(x$time_error)))
        avg_block <- c(avg_block, mean (abs(x$error)))
        neg_count <- c(neg_count, sum (x$time_error <0) + sum (x$error < 0))
      }
    }
  }
  
  data.frame(mul_ratios, min_mals, p_indexes, avg_time, avg_block, neg_count)
}

run_all_alpha <- function ()
{
  alphas <- seq(0,1,0.05)
  time_errs <- c()
  block_errs <- c()
  for (alpha in alphas) {
    x <- detect_all_information(alpha = alpha)
    time_errs <- c(time_errs, mean (x$time_error))
    block_errs <- c(block_errs, mean (x$error))
  }
  data.frame(alphas, time_errs, block_errs)
}

plot_all_alpha <- function ()
{
  y <- run_all_alpha()
  plot (time_errs ~ alphas, data = y, col = "red", pch = 1, lty = 1, type = "o", xlab = "Alpha", ylab = "Value", ylim = c(10,50))
  lines(y$block_errs ~ y$alphas, type = "o", col = "black", pch = 2, lty = 2)
  legend(x=0.3, y = 50, col = c("red","black"), lty =c(1,2), pch = c(1,2), c("Predicting error (minutes)", "Predicting error (number of blocks)"))
  y
}

detect_both_info_all_param <- function ()
{
  p_indexes <- c(20,30,40)
  down_thr <- c(20,30,40)
  down_rat <- c(0.75,1)
  windows <- c(0,1,5,10)
  uppers <- c(17.5,20,25)
  
  df <- data.frame("p_index" = as.numeric(),
                   "down_threshold" = as.numeric(),
                   "down_rate" = as.numeric(),
                   "window_size" = as.numeric(),
                   "upper_bound"  = as.numeric(),
                   "mean_time_error" = as.numeric(),
                   "mean_block_error" = as.numeric(),
                   "neg_count" = as.numeric()
                   )
  count = 1
  for (p in p_indexes) {
    for (d in down_thr) {
      for (d1 in down_rat) {
        for (w in windows) {
          for (u in uppers) {
            print (paste("Process",count))
            count <- count + 1
            dx <- detect_regression_avg_time_diff_all(predict_index = p, upper_bound = u, window_size = w, down_threshold = d, down_rate = d1)
            mean_time_error <- mean (dx$time_error)
            mean_block_error <- mean (dx$block_error)
            neg_count <- sum (dx$time_error <0) + sum (dx$block_error < 0)
            
            df[nrow(df)+1,] <- c(p,d,d1,w,u,
                                 mean_time_error,
                                 mean_block_error,
                                 neg_count)
          }
        }
      }
    }
  }
  df
}

# combien detection by average time and diff
detect_regression_avg_time_diff_all <- function (path = "/Users/qdang/workspace/Trusternity-client/data/2/",
                                        mul_ratio = 2,
                                        min_malicious_start = 150,
                                        predict_index = 1,
                                        streak_len = 10,
                                        upper_bound = 20,
                                        window_size = 0,
                                        down_threshold = 20,
                                        down_rate = 0.75) 
{
  # manual from https://github.com/coast-team/Trusternity-client/tree/master/data
  # malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 265, 245,
  #                       230, 251, 245, 227, 239, 223, 218, 253, 251)
  malicious_start <- c (234, 244, 232, 232, 253, 226, 252, 218, 227, 245,
                        230, 251, 245, 227, 239, 223, 245, 237, 210)
  df <- data.frame("exp_id" = as.numeric(),
                    "number_of_malicious" = as.numeric(),
                   "malicious_start" = as.numeric(),
                   "malicious_predict" =as.numeric(),
                   "time_error" = as.numeric(),   # different in minute between actual malicious point and prediction
                   "block_error" = as.numeric()
  )
  for (j in 1:10) {
    for (i in 1:19) {
      new_row <- detect_regression_avg_time_diff_onefile(predict_index = predict_index, upper_bound = upper_bound,
                                                         window_size = window_size, down_threshold = down_threshold,
                                                         down_rate = down_rate,
                                                         streak_len = streak_len,
                                                         fileid = i,
                                                         exp_id = j
      )
      # print (new_row)
      if (new_row[4] != -1 & !is.na(new_row[5])) {
        df[nrow(df) + 1,] <- new_row
      }
    }
  }
  
  
  plot (abs(df$block_error) ~ df$number_of_malicious, col = "red", xlim = c(1,19), ylim =c(0,60),
        type = "p", ylab = "Value", xlab = "Number of malicious", lty = 3, xaxt = "n", las = 2, pch = 19)
  axis(1, at=1:19, labels=1:19)
  # lines (df$mean_high_avg ~ df$number_of_malicious, col = "black", lty = 2, type = "o", pch = 2)
  # lines (df$longest_down_streak ~ df$number_of_malicious, col = "blue", lty = 1, type = "o", pch = 3)
  lines (abs(df$time_error) ~ df$number_of_malicious, col = "black", lty = 4, pch = 5, type = "p")
  
  legend(x=5,y=60,col = c("red","black"), lty=c(3,5), c("Prediction error (number of blocks)",
                                                        "Prediction error (minutes)"),
         pch = c(19,5))
  
  l1 <- lm (abs(df$block_error) ~ df$number_of_malicious)
  l2 <- lm (abs(df$time_error) ~ df$number_of_malicious)
  
  abline (l1, col = "red", lty = 3)
  abline (l2, col = "black", lty = 5)
  
  print (paste("Time:", mean (abs(df$time_error))))
  print (paste("Block:", mean (abs(df$block_error))))
  print (paste("Negative count:", sum (df$time_error <0) + sum (df$error < 0)))
  df
}

detect_regression_avg_time_diff_onefile <- function (path = "/Users/qdang/workspace/Trusternity-client/data/",
                                                 mul_ratio = 2,
                                                 min_malicious_start = 150,
                                                 predict_index = 1,
                                                 upper_bound = 17.5,
                                                 streak_len = 10,
                                                 window_size = 0,
                                                 down_threshold = 20,
                                                 down_rate = 0.75,
                                                 fileid = 1,
                                                 exp_id = 1) 
{
  i = fileid
    
  file_name = paste(path,exp_id,"/","blocks_info_40-",i,".json.csv", sep = "")
  info_file = paste (path,exp_id,"/","transition_block_number.csv", sep = "")
  
  if (!file.exists(file_name)) {
    print ('No file')
    return (c(-1,-1,-1,-1,-1,-1))
  }
  cur_df <- read.csv(file_name)
  info <- read.csv (info_file)
  
  malicious_start <- info[info$mining_node == fileid,]$block_number
  
  predict_pos_avg <- detect_anomaly_avg(avg = cur_df$avg[50:nrow(cur_df)], num = cur_df$num, multiple_ratio = mul_ratio, min_malicious_num = min_malicious_start,
                                        num_mal = i, correct_mal_pos = malicious_start,
                                        upper_bound = upper_bound, streak_len = streak_len) + 50
  predict_pos_diff <- detect_anomaly_series (x = cur_df$diff[50:length(cur_df$diff)], average_size = window_size, down_threshold = down_threshold,
                                             down_rate = down_rate) +50
  
  predict_pos <- c(predict_pos_avg, predict_pos_diff)
  predict_pos <- sort(predict_pos, decreasing = FALSE)
  
  if (length(predict_pos) == 0) {
    return(c(exp_id,fileid, malicious_start, -1, -1, -1))
    stop()
  }
  
  p_index = min (length(predict_pos), predict_index)
  
  
  # Difficulty
  plot (cur_df$diff ~ cur_df$num, col = "black", lty = 1, pch = 1, type = "l", main = paste("Difficulty-based detection. Number of malicious:", fileid), 
        xlab = "Number of blocks", ylab = "Difficulty")
  abline (v = predict_pos[p_index], lty = 2, lwd = 2, pch = 4)
  for (p in predict_pos_diff) {
    abline (v = p, col = "blue", lty = 2, pch = 2)
  }
  
  
  # Average block
  plot (cur_df$avg ~ cur_df$num, col = "red", lty = 1, pch = 1, type = "o", 
        main = paste("Average block time-based detection. Number of malicious:", fileid),
        xlab = "Number of blocks", ylab = "Block time")
  
  
  abline (v = malicious_start, col = "red", lty = 2, pch = 3, lwd = 3)
  abline (h = upper_bound, col = "green", lty= 3)
  
  abline (v = predict_pos[p_index], lty = 3, lwd = 2, pch = 4)
  
  for (p in predict_pos_avg) {
    abline (v = p, col = "blue", lty = 2, pch = 2)
  }
  
  # print (predict_pos_avg)
  # print (predict_pos_diff)
  
  time_error <- (cur_df$time[predict_pos[p_index]] - cur_df$time[malicious_start]) / 60
  block_error <- predict_pos[p_index] - malicious_start
  c(exp_id,fileid, malicious_start, predict_pos[p_index], time_error, block_error)
}